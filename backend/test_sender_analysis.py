from sender_analysis import analyze_sender_identity


def test_detects_brand_spoofing_and_identity_mismatches():
    result = analyze_sender_identity({
        "from": {"display_name": "Microsoft Security", "email": "security@random-domain.example", "domain": "random-domain.example"},
        "reply_to": {"display_name": None, "email": "support@another-domain.example", "domain": "another-domain.example"},
        "return_path": {"display_name": None, "email": "mailer@third-domain.example", "domain": "third-domain.example"},
    })

    codes = {finding["code"] for finding in result["findings"]}
    assert {"display_name_spoofing", "brand_impersonation", "from_reply_to_mismatch", "from_return_path_mismatch", "domain_mismatch"} <= codes
    assert result["suspicious"] is True


def test_detects_punycode_and_brand_subdomain_abuse():
    result = analyze_sender_identity({
        "from": {"display_name": "Account Team", "email": "notice@xn--microsft-abc.example", "domain": "xn--microsft-abc.example"},
        "reply_to": None,
        "return_path": None,
    })

    assert "punycode_domain" in {finding["code"] for finding in result["findings"]}
