"""Context-aware social-engineering and legitimate ESP pattern analysis."""

import re

SOCIAL_PATTERNS = {
    "urgency": (r"\b(urgent|immediately|within \d+ (minutes?|hours?)|act now|time[- ]sensitive)\b", 5),
    "fear": (r"\b(permanently deleted|lose access|security breach|compromised|final warning)\b", 6),
    "account_suspension": (r"\b(account (?:has been |will be )?(?:suspended|disabled|locked)|access (?:has been |will be )?removed)\b", 8),
    "payment_pressure": (r"\b(pay now|payment (?:is )?(?:overdue|failed)|past due|avoid (?:a )?late fee)\b", 7),
    "credential_request": (r"\b(verify|confirm|enter|submit|update) (?:your )?(?:password|credentials|login details)\b", 12),
    "mfa_request": (r"\b(?:share|send|provide|enter) (?:your )?(?:mfa|2fa|one[- ]time|verification|security) code\b", 8),
    "unusual_request": (r"\b(gift cards?|wire transfer|crypto(?:currency)?|bank account details?|purchase .*cards?)\b", 12),
}
NORMAL_PATTERNS = {
    "shipping_notification": r"\b(order|package|shipment).{0,40}\b(shipped|delivered|on (?:the )?way|tracking)\b",
    "receipt": r"\b(receipt|thanks for (?:your )?(?:order|purchase)|payment received)\b",
    "marketing_email": r"\b(sale|offer|save \d+%|shop now|new arrivals)\b",
    "newsletter": r"\b(newsletter|weekly update|monthly update)\b",
    "password_reset": r"\b(password reset|reset your password|reset link)\b",
    "account_notification": r"\b(account notification|new sign[- ]in|account activity|security alert)\b",
}


def analyze_content(subject: str, body_text: str, sender_identity: dict | None = None) -> dict:
    text = f"{subject or ''}\n{body_text or ''}".lower()
    findings, matched = [], set()
    for kind, (pattern, weight) in SOCIAL_PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            matched.add(kind)
            findings.append({"type": kind, "risk_contribution": weight})
    normal_patterns = [kind for kind, pattern in NORMAL_PATTERNS.items() if re.search(pattern, text, re.IGNORECASE)]
    high_pressure_credential = "credential_request" in matched and bool(matched & {"urgency", "fear", "account_suspension"})
    if high_pressure_credential:
        findings.append({"type": "high_pressure_credential_request", "risk_contribution": 10})
    score = sum(finding["risk_contribution"] for finding in findings)
    if normal_patterns and not high_pressure_credential and matched <= {"payment_pressure"}:
        score = max(0, score - 5)
    assessment = (
        "High-pressure credential request detected. Treat as substantially suspicious." if high_pressure_credential else
        "Social-engineering language detected. Review alongside sender and authentication evidence." if matched else
        "Language matches a normal transactional or account-notification pattern." if normal_patterns else
        "No prominent social-engineering pattern detected."
    )
    if (sender_identity or {}).get("suspicious"):
        findings.append({"type": "sender_impersonation_context", "risk_contribution": 0})
    return {"findings": findings, "normal_patterns": normal_patterns, "risk_contribution": min(40, score), "high_pressure_credential": high_pressure_credential, "assessment": assessment}


def analyze_esp(msg, urls: list, authentication: dict, sender_identity: dict, content: dict, mime_analysis: dict) -> dict:
    """Recognize ESP context without treating any provider as intrinsically safe."""
    header_blob = "\n".join(f"{name}: {value}".lower() for name, value in msg.items())
    providers = []
    for provider, markers in {"SendGrid": ("x-sg-", "sendgrid"), "Mailgun": ("x-mailgun", "mailgun"), "Mailchimp": ("x-mc-", "mailchimp"), "Amazon SES": ("x-ses-", "amazonses"), "Postmark": ("x-pm-", "postmarkapp")}.items():
        if any(marker in header_blob for marker in markers):
            providers.append(provider)
    tracking_url = any(any(marker in (url.get("domain") or "") for marker in ("sendgrid.net", "mailchimp.com", "mandrillapp.com", "amazonses.com", "mailgun.org", "postmarkapp.com")) for url in urls)
    unsubscribe_url = any(any(marker in (url.get("domain") or "") for marker in ("unsubscribe", "list-manage", "mailchimp")) for url in urls)
    list_unsubscribe = bool(msg.get("List-Unsubscribe"))
    auth_aligned = authentication.get("dmarc", {}).get("state") == "PASS"
    sender_codes = {finding.get("code") for finding in sender_identity.get("findings", [])}
    sender_consistent = not (sender_codes - {"from_return_path_mismatch"})
    normal_behavior = bool(content.get("normal_patterns")) and not content.get("high_pressure_credential")
    multipart_html = bool(mime_analysis.get("multipart")) and any(part.get_content_type() == "text/html" for part in msg.walk())
    corroboration = sum((auth_aligned, sender_consistent, normal_behavior, list_unsubscribe or unsubscribe_url, multipart_html))
    strong_legitimacy = bool(providers or tracking_url) and corroboration >= 4
    evidence = []
    if providers: evidence.append(f"ESP headers: {', '.join(providers)}")
    if tracking_url: evidence.append("ESP tracking URL")
    if list_unsubscribe: evidence.append("List-Unsubscribe header")
    if unsubscribe_url: evidence.append("unsubscribe URL")
    if multipart_html: evidence.append("multipart HTML")
    if auth_aligned: evidence.append("aligned authentication")
    if sender_consistent: evidence.append("consistent sender identity")
    if normal_behavior: evidence.append("normal email behavior")
    assessment = "Multiple independent legitimate-mail signals corroborate the ESP delivery context." if strong_legitimacy else "ESP infrastructure observed but not treated as safe on its own." if (providers or tracking_url) else "No recognized ESP context found."
    return {"providers": providers, "tracking_url": tracking_url, "list_unsubscribe": list_unsubscribe, "unsubscribe_url": unsubscribe_url, "multipart_html": multipart_html, "auth_aligned": auth_aligned, "sender_consistent": sender_consistent, "normal_behavior": normal_behavior, "strong_legitimacy": strong_legitimacy, "risk_contribution": -8 if strong_legitimacy else 0, "assessment": assessment, "evidence": evidence}
