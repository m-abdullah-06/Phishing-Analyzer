"""
homograph.py — Detects lookalike / typosquatted domains.

Compares the sender's domain against a list of commonly impersonated brands
using Levenshtein edit distance, plus checks for punycode (IDN homograph attacks)
and common character-substitution tricks (rn -> m, 0 -> o, 1 -> l, etc).
"""

COMMONLY_SPOOFED_BRANDS = [
    "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
    "bankofamerica.com", "wellsfargo.com", "chase.com", "netflix.com",
    "facebook.com", "instagram.com", "linkedin.com", "dhl.com", "fedex.com",
    "usps.com", "irs.gov", "outlook.com", "office365.com", "dropbox.com",
    "adobe.com", "docusign.com", "americanexpress.com", "citibank.com",
]


def levenshtein(a: str, b: str) -> int:
    """Standard edit distance — minimum insertions/deletions/substitutions to turn a into b."""
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _normalize_lookalikes(domain: str) -> str:
    """Collapse common visual substitution tricks to reveal the intended brand name."""
    replacements = {
        'rn': 'm', '0': 'o', '1': 'l', '3': 'e', '5': 's', '@': 'a', 'vv': 'w',
    }
    normalized = domain
    for fake, real in replacements.items():
        normalized = normalized.replace(fake, real)
    return normalized


def check_homograph(domain: str) -> dict:
    if not domain:
        return {"suspicious": False, "matched_brand": None, "distance": None, "detail": None}

    domain = domain.lower()

    if domain.startswith('xn--') or '.xn--' in domain:
        return {
            "suspicious": True,
            "matched_brand": None,
            "distance": None,
            "detail": f"Domain '{domain}' uses punycode encoding (xn--), commonly used to "
                      f"disguise lookalike Unicode characters as a trusted domain (IDN homograph attack).",
        }

    if domain in COMMONLY_SPOOFED_BRANDS:
        return {"suspicious": False, "matched_brand": None, "distance": 0,
                "detail": "Domain exactly matches a known legitimate brand domain."}

    normalized_domain = _normalize_lookalikes(domain)

    for brand in COMMONLY_SPOOFED_BRANDS:
        distance = levenshtein(domain, brand)
        if distance <= 2:
            return {
                "suspicious": True,
                "matched_brand": brand,
                "distance": distance,
                "detail": f"Domain '{domain}' is {distance} character(s) away from '{brand}' — "
                          f"likely typosquatting a trusted brand.",
            }
        if normalized_domain == brand.replace('.', '').replace('com', '') + '.com' or normalized_domain == brand:
            return {
                "suspicious": True,
                "matched_brand": brand,
                "distance": distance,
                "detail": f"Domain '{domain}' uses character substitution to visually resemble '{brand}'.",
            }

        brand_core = brand.split('.')[0]
        if len(brand_core) >= 4 and brand_core in normalized_domain and domain != brand:
            return {
                "suspicious": True,
                "matched_brand": brand,
                "distance": None,
                "detail": f"Domain '{domain}' contains '{brand_core}' embedded in a longer domain — "
                          f"a common typosquatting pattern (e.g. 'brandname-secure-login.tld').",
            }

    return {"suspicious": False, "matched_brand": None, "distance": None,
            "detail": "No close match to commonly spoofed brand domains."}
