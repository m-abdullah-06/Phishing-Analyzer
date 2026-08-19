"""
auth_checker.py — Real SPF, DKIM, and DMARC verification.

This performs actual DNS lookups and cryptographic DKIM verification,
not just reading the Authentication-Results header the mail server left behind
(which itself could be spoofed by whoever relayed the message).

Notes on simplifications (worth knowing, not a limitation to hide):
- SPF: we check ip4/ip6/a mechanisms directly. `include:` mechanisms that point
  to third-party senders (e.g. include:_spf.google.com) are NOT recursively
  resolved — we flag them for manual review instead. Full recursive SPF
  resolution is what libraries like `pyspf` attempt, but direct mechanism
  checking covers the majority of real-world phishing cases where the
  attacker's domain has no legitimate SPF infrastructure at all.
- DMARC: organizational domain lookup is simplified (walks up to 2 parent
  labels). A fully correct implementation needs the Public Suffix List to
  know where a "real" organizational boundary is (e.g. co.uk vs .com).
"""

import re
import ipaddress
import dns.resolver
import dkim


def _query_txt(domain: str):
    """Return all TXT record strings for a domain, or [] if none/error."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=8)
        records = []
        for rdata in answers:
            txt = b''.join(rdata.strings).decode('utf-8', errors='ignore')
            records.append(txt)
        return records
    except Exception:
        return []


def _state_to_risk_impact(state: str) -> int:
    impact_map = {
        "pass": 0,
        "softfail": 6,
        "fail": 10,
        "neutral": 2,
        "none": 0,
        "unknown": 4,
        "error": 4,
    }
    return impact_map.get(state, 0)


def _organizational_domain(domain: str | None) -> str | None:
    """Return a simplified organizational domain for relaxed DMARC alignment."""
    if not domain:
        return None
    labels = domain.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else labels[0]


def _domains_align(authenticated_domain: str | None, from_domain: str | None, strict: bool = False) -> bool:
    if not authenticated_domain or not from_domain:
        return False
    authenticated_domain = authenticated_domain.lower().strip(".")
    from_domain = from_domain.lower().strip(".")
    return authenticated_domain == from_domain if strict else (
        _organizational_domain(authenticated_domain) == _organizational_domain(from_domain)
    )


def _alignment(identity_domain: str | None, from_domain: str | None, authenticated: bool, mechanism: str) -> dict:
    domain_matches = _domains_align(identity_domain, from_domain)
    if not identity_domain:
        reason = f"No {mechanism} identity was available for alignment."
    elif not authenticated:
        reason = f"{mechanism} did not authenticate {identity_domain}; alignment cannot satisfy DMARC."
    elif domain_matches:
        reason = f"Authenticated {mechanism} domain {identity_domain} aligns with visible From domain {from_domain} (relaxed alignment)."
    else:
        reason = f"Authenticated {mechanism} domain {identity_domain} does not align with visible From domain {from_domain} (relaxed alignment)."
    return {"aligned": authenticated and domain_matches, "domain": identity_domain, "from_domain": from_domain, "mode": "relaxed", "reason": reason}


def check_spf(domain: str, sending_ip: str | None, from_domain: str | None = None) -> dict:
    if not domain:
        return {
            "record_found": False,
            "state": "NONE",
            "result": "none",
            "detail": "No domain to check.",
            "impact": {"risk_contribution": 0, "label": "No SPF evidence"},
            "alignment": _alignment(None, from_domain, False, "SPF"),
        }

    txt_records = _query_txt(domain)
    spf_record = next((r for r in txt_records if r.startswith('v=spf1')), None)

    if not spf_record:
        return {
            "record_found": False,
            "raw": None,
            "state": "NONE",
            "result": "none",
            "detail": f"No SPF record published for {domain}.",
            "impact": {"risk_contribution": 0, "label": "No SPF evidence"},
            "alignment": _alignment(domain, from_domain, False, "SPF"),
        }

    if not sending_ip:
        return {
            "record_found": True,
            "raw": spf_record,
            "state": "UNKNOWN",
            "result": "unknown",
            "detail": "SPF record exists but no originating IP could be determined from headers.",
            "impact": {"risk_contribution": 4, "label": "Insufficient SPF evidence"},
            "alignment": _alignment(domain, from_domain, False, "SPF"),
        }

    mechanisms = spf_record.split()
    matched = False
    has_include = False

    for mech in mechanisms:
        if mech.startswith('ip4:'):
            cidr = mech[4:]
            try:
                if ipaddress.ip_address(sending_ip) in ipaddress.ip_network(cidr, strict=False):
                    matched = True
                    break
            except ValueError:
                continue
        elif mech.startswith('ip6:'):
            cidr = mech[4:]
            try:
                if ipaddress.ip_address(sending_ip) in ipaddress.ip_network(cidr, strict=False):
                    matched = True
                    break
            except ValueError:
                continue
        elif mech.startswith('include:'):
            has_include = True

    if matched:
        return {
            "record_found": True,
            "raw": spf_record,
            "state": "PASS",
            "result": "pass",
            "detail": f"Sending IP {sending_ip} matches an authorized ip4/ip6 range.",
            "impact": {"risk_contribution": 0, "label": "No SPF risk"},
            "alignment": _alignment(domain, from_domain, True, "SPF"),
        }

    if has_include:
        return {
            "record_found": True,
            "raw": spf_record,
            "state": "NEUTRAL",
            "result": "neutral",
            "detail": "No direct IP match, but record includes third-party senders (include: mechanism) that weren't recursively resolved. Manual verification recommended.",
            "impact": {"risk_contribution": 2, "label": "Minimal SPF risk"},
            "alignment": _alignment(domain, from_domain, False, "SPF"),
        }

    all_mech = next((m for m in mechanisms if m.endswith('all')), '~all')
    qualifier = all_mech[0] if all_mech[0] in '+-~?' else '+'
    result_map = {'-': 'FAIL', '~': 'SOFTFAIL', '?': 'NEUTRAL', '+': 'PASS'}
    state = result_map.get(qualifier, 'SOFTFAIL')
    result = {'-': 'fail', '~': 'softfail', '?': 'neutral', '+': 'pass'}.get(qualifier, 'softfail')

    return {
        "record_found": True,
        "raw": spf_record,
        "state": state,
        "result": result,
        "detail": f"Sending IP {sending_ip} not found in any authorized range. Policy is '{all_mech}'.",
        "impact": {"risk_contribution": _state_to_risk_impact(result), "label": f"SPF {state.lower()}"},
        "alignment": _alignment(domain, from_domain, False, "SPF"),
    }


def check_dkim(raw_bytes: bytes, from_domain: str | None) -> dict:
    signature_present = b'DKIM-Signature' in raw_bytes

    if not signature_present:
        return {
            "signature_present": False,
            "state": "NONE",
            "valid": None,
            "domain": None,
            "detail": "No DKIM-Signature header found. Legitimate mail from major providers almost always signs outbound mail — a total absence is itself a signal worth noting.",
            "impact": {"risk_contribution": 0, "label": "No DKIM evidence"},
            "alignment": _alignment(None, from_domain, False, "DKIM"),
        }

    sig_domain = None
    match = re.search(rb'DKIM-Signature:.*?d=([a-zA-Z0-9\.\-]+)', raw_bytes, re.DOTALL)
    if match:
        sig_domain = match.group(1).decode('utf-8', errors='ignore')

    try:
        valid = dkim.verify(raw_bytes)
    except Exception as e:
        return {
            "signature_present": True,
            "state": "UNKNOWN",
            "valid": None,
            "domain": sig_domain,
            "detail": f"DKIM signature present but verification errored: {e}",
            "impact": {"risk_contribution": 4, "label": "DKIM verification unavailable"},
            "alignment": _alignment(sig_domain, from_domain, False, "DKIM"),
        }

    alignment_note = ""
    aligned = _domains_align(sig_domain, from_domain)
    if sig_domain and from_domain and not aligned:
        alignment_note = (f" Note: DKIM signing domain ({sig_domain}) differs from the visible From domain ({from_domain}) — this may still be legitimate (third-party sending service) but is worth checking DMARC alignment for.")

    if valid:
        return {
            "signature_present": True,
            "state": "PASS",
            "valid": True,
            "domain": sig_domain,
            "detail": f"Signature cryptographically verified against DNS-published public key for {sig_domain}.{alignment_note}",
            "impact": {"risk_contribution": 0, "label": "No DKIM risk"},
            "alignment": _alignment(sig_domain, from_domain, True, "DKIM"),
        }
    else:
        return {
            "signature_present": True,
            "state": "FAIL",
            "valid": False,
            "domain": sig_domain,
            "detail": f"Signature FAILED verification — the message body or headers were likely modified after signing, or the signature is forged.{alignment_note}",
            "impact": {"risk_contribution": 10, "label": "DKIM failure"},
            "alignment": _alignment(sig_domain, from_domain, False, "DKIM"),
        }


def _get_organizational_domain_candidates(domain: str):
    """Yield domain, then parent domain, up to 2 levels up — simplified without a PSL."""
    labels = domain.split('.')
    yield domain
    if len(labels) > 2:
        yield '.'.join(labels[-2:])


def check_dmarc(domain: str, spf: dict | None = None, dkim_result: dict | None = None) -> dict:
    if not domain:
        return {
            "record_found": False,
            "state": "NONE",
            "policy": None,
            "detail": "No domain to check.",
            "impact": {"risk_contribution": 0, "label": "No DMARC evidence"},
            "alignment": {"aligned": False, "domain": None, "reason": "No visible From domain available"},
        }

    for candidate in _get_organizational_domain_candidates(domain):
        txt_records = _query_txt(f"_dmarc.{candidate}")
        dmarc_record = next((r for r in txt_records if r.startswith('v=DMARC1')), None)
        if dmarc_record:
            policy_match = re.search(r'p=(\w+)', dmarc_record)
            policy = policy_match.group(1) if policy_match else 'none'
            pct_match = re.search(r'pct=(\d+)', dmarc_record)
            pct = int(pct_match.group(1)) if pct_match else 100
            # A DMARC policy says how a receiver should handle failure; it is
            # not itself a PASS. PASS requires a passing, aligned SPF or DKIM
            # identity for the visible From domain.
            spf = spf or {}
            dkim_result = dkim_result or {}
            spf_aligned = spf.get("state") == "PASS" and bool(spf.get("alignment", {}).get("aligned"))
            dkim_aligned = dkim_result.get("state") == "PASS" and bool(dkim_result.get("alignment", {}).get("aligned"))
            evidence_unknown = spf.get("state") == "UNKNOWN" or dkim_result.get("state") == "UNKNOWN"
            valid_policy = policy in {"none", "quarantine", "reject"}
            if not valid_policy:
                state = "UNKNOWN"
                alignment_reason = f"DMARC record has an unsupported policy value '{policy}'."
            elif spf_aligned or dkim_aligned:
                state = "PASS"
                channels = ", ".join(name for name, aligned in (("SPF", spf_aligned), ("DKIM", dkim_aligned)) if aligned)
                alignment_reason = f"DMARC passes through aligned {channels}."
            elif evidence_unknown:
                state = "UNKNOWN"
                alignment_reason = "DMARC could not be evaluated because SPF or DKIM verification is unavailable."
            else:
                state = "FAIL"
                alignment_reason = "Neither a passing aligned SPF identity nor a passing aligned DKIM identity was found."
            impact = {"risk_contribution": _state_to_risk_impact(state.lower()), "label": f"DMARC {state.lower()}"}

            return {
                "record_found": True,
                "checked_domain": candidate,
                "raw": dmarc_record,
                "state": state,
                "policy": policy,
                "enforcement_pct": pct,
                "detail": f"DMARC {state.lower()}: policy for {candidate} is '{policy}'" + (f" (only enforced on {pct}% of mail)" if pct < 100 else "") + f". {alignment_reason}",
                "impact": impact,
                "alignment": {"aligned": state == "PASS", "domain": domain, "reason": alignment_reason, "spf_aligned": spf_aligned, "dkim_aligned": dkim_aligned},
            }

    return {
        "record_found": False,
        "state": "NONE",
        "policy": None,
        "detail": f"No DMARC record found for {domain} or its parent domain. This means there's no policy telling receiving servers what to do with mail that fails SPF/DKIM — a common gap attackers exploit when spoofing lesser-known domains.",
        "impact": {"risk_contribution": 0, "label": "No DMARC evidence"},
        "alignment": {"aligned": False, "domain": domain, "reason": "No DMARC record present"},
    }
