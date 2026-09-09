"""Structured sender-identity analysis for phishing and impersonation detection."""

from homograph import check_homograph


BRAND_IDENTITIES = {
    "microsoft": {"microsoft.com", "office365.com", "outlook.com"},
    "google": {"google.com", "gmail.com"},
    "paypal": {"paypal.com"},
    "apple": {"apple.com"},
    "amazon": {"amazon.com"},
    "docusign": {"docusign.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "netflix": {"netflix.com"},
}

FINDING_WEIGHTS = {
    "display_name_spoofing": 18,
    "from_reply_to_mismatch": 8,
    "from_return_path_mismatch": 8,
    "domain_mismatch": 5,
    "lookalike_domain": 18,
    "punycode_domain": 20,
    "suspicious_subdomain": 15,
    "brand_impersonation": 20,
}


def _domain(address: dict | None) -> str | None:
    return (address or {}).get("domain", None)


def _brand_in_text(value: str | None) -> str | None:
    text = (value or "").lower()
    for brand in BRAND_IDENTITIES:
        if brand in text:
            return brand
    return None


def _is_expected_brand_domain(domain: str | None, brand: str) -> bool:
    if not domain:
        return False
    domain = domain.lower().strip(".")
    return any(domain == expected or domain.endswith(f".{expected}") for expected in BRAND_IDENTITIES[brand])


def _add(findings: list, code: str, detail: str, severity: str = "high", domain: str | None = None, brand: str | None = None):
    findings.append({
        "code": code,
        "severity": severity,
        "risk_contribution": FINDING_WEIGHTS[code],
        "detail": detail,
        "domain": domain,
        "brand": brand,
    })


def analyze_sender_identity(headers: dict) -> dict:
    """Analyze all sender identities, returning reviewable evidence and risk impact."""
    from_address = headers.get("from") or {}
    reply_to = headers.get("reply_to")
    return_path = headers.get("return_path")
    from_domain = _domain(from_address)
    reply_domain = _domain(reply_to)
    return_domain = _domain(return_path)
    display_name = from_address.get("display_name")
    findings = []

    display_brand = _brand_in_text(display_name)
    if display_brand and not _is_expected_brand_domain(from_domain, display_brand):
        _add(
            findings, "display_name_spoofing",
            f"Display name claims {display_brand.title()}, but From domain '{from_domain or 'missing'}' is not an expected {display_brand.title()} domain.",
            domain=from_domain, brand=display_brand,
        )
        _add(
            findings, "brand_impersonation",
            f"The visible sender identity presents the {display_brand.title()} brand without a matching sender domain.",
            domain=from_domain, brand=display_brand,
        )

    if from_domain and reply_domain and from_domain != reply_domain:
        _add(findings, "from_reply_to_mismatch", f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'. Replies are redirected to a different domain.", "medium", reply_domain)
    if from_domain and return_domain and from_domain != return_domain:
        _add(findings, "from_return_path_mismatch", f"From domain '{from_domain}' differs from Return-Path domain '{return_domain}'. Bounce handling uses a different identity.", "medium", return_domain)

    identity_domains = [domain for domain in (from_domain, reply_domain, return_domain) if domain]
    if len(set(identity_domains)) >= 3:
        _add(findings, "domain_mismatch", "From, Reply-To, and Return-Path use three distinct domains, creating an inconsistent sender identity.", "medium")

    for domain in dict.fromkeys(identity_domains):
        if domain.startswith("xn--") or ".xn--" in domain:
            _add(findings, "punycode_domain", f"Sender identity domain '{domain}' uses punycode (xn--), which can conceal lookalike Unicode characters.", domain=domain)

        lookalike = check_homograph(domain)
        if lookalike.get("suspicious") and not (domain.startswith("xn--") or ".xn--" in domain):
            _add(findings, "lookalike_domain", lookalike["detail"], domain=domain, brand=lookalike.get("matched_brand"))

        brand = _brand_in_text(domain)
        if brand and not _is_expected_brand_domain(domain, brand):
            labels = domain.split(".")
            if brand in labels or any(label.startswith(f"{brand}-") or label.endswith(f"-{brand}") for label in labels):
                _add(findings, "suspicious_subdomain", f"Domain '{domain}' places the {brand.title()} brand in a subdomain/label outside the legitimate {brand.title()} domain hierarchy.", domain=domain, brand=brand)

    # Dedupe overlap from the same detector/domain while retaining different evidence types.
    unique_findings = []
    seen = set()
    for finding in findings:
        key = (finding["code"], finding.get("domain"), finding.get("brand"))
        if key not in seen:
            unique_findings.append(finding)
            seen.add(key)

    score = min(100, sum(finding["risk_contribution"] for finding in unique_findings))
    return {
        "display_name": display_name,
        "from": from_address,
        "reply_to": reply_to,
        "return_path": return_path,
        "findings": unique_findings,
        "risk_contribution": score,
        "suspicious": bool(unique_findings),
    }
