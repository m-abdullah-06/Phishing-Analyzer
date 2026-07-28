"""
email_parser.py — Parses raw .eml content into structured data.

Handles:
- Header extraction (From, Reply-To, Return-Path, Subject, Message-ID)
- Received header chain reconstruction + originating IP detection
- URL extraction from both plain text and HTML bodies
- Attachment extraction with SHA256 hashing
"""

import re
import hashlib
import ipaddress
from email import message_from_bytes, policy
from email.utils import parseaddr
from bs4 import BeautifulSoup

URL_REGEX = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
IP_IN_BRACKETS_REGEX = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
IP_ANYWHERE_REGEX = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1',
    '.docm', '.xlsm', '.pptm', '.iso', '.lnk', '.wsf', '.hta', '.msi'
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'buff.ly',
    'is.gd', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy'
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.click', '.link', '.country', '.stream', '.icu', '.cam'
}


def parse_raw_email(raw_bytes: bytes):
    """Parse raw email bytes into a Message object using modern policy."""
    return message_from_bytes(raw_bytes, policy=policy.default)


def extract_address_parts(header_value: str):
    """Given a header like 'PayPal <support@paypal.com>', return display name, email, domain."""
    if not header_value:
        return {"display_name": None, "email": None, "domain": None}
    display_name, email_addr = parseaddr(header_value)
    domain = email_addr.split('@')[-1].lower() if '@' in email_addr else None
    return {
        "display_name": display_name or None,
        "email": email_addr or None,
        "domain": domain,
    }


def get_header_summary(msg):
    """Extract core headers and detect basic spoofing mismatches."""
    from_parts = extract_address_parts(msg.get('From', ''))
    reply_to_parts = extract_address_parts(msg.get('Reply-To', '')) if msg.get('Reply-To') else None
    return_path_parts = extract_address_parts(msg.get('Return-Path', '')) if msg.get('Return-Path') else None

    spoofing_flags = []

    if reply_to_parts and reply_to_parts["domain"] and from_parts["domain"]:
        if reply_to_parts["domain"] != from_parts["domain"]:
            spoofing_flags.append(
                f"Reply-To domain ({reply_to_parts['domain']}) differs from From domain ({from_parts['domain']}) — "
                f"replies would go somewhere the sender name doesn't suggest."
            )

    if return_path_parts and return_path_parts["domain"] and from_parts["domain"]:
        if return_path_parts["domain"] != from_parts["domain"]:
            spoofing_flags.append(
                f"Return-Path domain ({return_path_parts['domain']}) differs from From domain ({from_parts['domain']}) — "
                f"bounce handling doesn't match the claimed sender."
            )

    return {
        "from": from_parts,
        "reply_to": reply_to_parts,
        "return_path": return_path_parts,
        "subject": msg.get('Subject', ''),
        "message_id": msg.get('Message-ID', ''),
        "date": msg.get('Date', ''),
        "spoofing_flags": spoofing_flags,
    }


def is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_global
    except ValueError:
        return False


def extract_received_chain(msg):
    """
    Received headers are prepended — the topmost is the most recent hop,
    the bottommost is closest to the original sender.
    We reverse to read origin-first, and pull the first public IP we find
    as the likely originating server.
    """
    received_headers = msg.get_all('Received', [])
    chain = []
    origin_ip = None

    # Reverse so index 0 = earliest (closest to true sender)
    for idx, header in enumerate(reversed(received_headers)):
        ip_match = IP_IN_BRACKETS_REGEX.search(header) or IP_ANYWHERE_REGEX.search(header)
        ip = ip_match.group(1) if ip_match else None
        chain.append({"hop": idx + 1, "raw": header.strip()[:200], "ip": ip})
        if ip and origin_ip is None and is_public_ip(ip):
            origin_ip = ip

    return chain, origin_ip


def _get_body_parts(msg):
    """Walk the MIME tree, return (plain_text, html_text)."""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == 'attachment':
                continue
            try:
                payload = part.get_content()
            except Exception:
                continue
            if content_type == 'text/plain' and isinstance(payload, str):
                plain += payload
            elif content_type == 'text/html' and isinstance(payload, str):
                html += payload
    else:
        try:
            payload = msg.get_content()
            if msg.get_content_type() == 'text/html':
                html = payload
            else:
                plain = payload
        except Exception:
            pass
    return plain, html


def extract_urls(msg):
    """Extract unique URLs from plain text and HTML bodies (including href attributes)."""
    plain, html = _get_body_parts(msg)
    urls = set(URL_REGEX.findall(plain))

    if html:
        urls.update(URL_REGEX.findall(html))
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if href.startswith('http'):
                    urls.add(href)
        except Exception:
            pass

    results = []
    for url in urls:
        clean_url = url.rstrip('.,)\'"')
        domain_match = re.search(r'https?://([^/:\s]+)', clean_url)
        domain = domain_match.group(1).lower() if domain_match else clean_url
        is_shortener = domain in URL_SHORTENERS
        suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        defanged = clean_url.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')
        results.append({
            "url": clean_url,
            "defanged": defanged,
            "domain": domain,
            "is_shortener": is_shortener,
            "suspicious_tld": suspicious_tld,
        })
    return results


def extract_attachments(msg):
    """Find attachments, compute SHA256, flag dangerous extensions."""
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition != 'attachment' and not filename:
            continue

        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None

        if not payload:
            continue

        sha256 = hashlib.sha256(payload).hexdigest()
        ext = ''
        if filename and '.' in filename:
            ext = '.' + filename.rsplit('.', 1)[-1].lower()

        attachments.append({
            "filename": filename or "unnamed",
            "sha256": sha256,
            "size_bytes": len(payload),
            "extension": ext,
            "dangerous_extension": ext in DANGEROUS_EXTENSIONS,
        })

    return attachments
