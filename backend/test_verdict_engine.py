from verdict_engine import classify_email_type, determine_final_verdict, calculate_risk_profile, determine_risk_band


def test_determine_final_verdict_is_rule_based():
    # MALICIOUS threshold is >=90
    assert determine_final_verdict(95) == "malicious"
    # HIGH RISK threshold is >=70 and <90
    assert determine_final_verdict(85) == "suspicious"
    # SUSPICIOUS threshold is >=50 and <70
    assert determine_final_verdict(55) == "suspicious"
    # LOW RISK threshold is >=25 and <50 → maps to clean
    assert determine_final_verdict(45) == "clean"
    assert determine_final_verdict(10) == "clean"


def test_determine_risk_band_uses_critical_override():
    assert determine_risk_band(35, critical_indicator=False) == "LOW RISK"
    assert determine_risk_band(35, critical_indicator=True) == "HIGH RISK"
    assert determine_risk_band(90, critical_indicator=False) == "MALICIOUS"


def test_classify_email_type_uses_indicator_signals():
    result = calculate_risk_profile(
        headers={"subject": "Urgent account security action required", "spoofing_flags": ["Reply-To domain differs from From domain"]},
        spf={"result": "fail"},
        dkim={"signature_present": False},
        dmarc={"record_found": False},
        homograph_result={"suspicious": True},
        urls=[{"vt_malicious": 2, "suspicious_tld": False, "is_shortener": False}],
        attachments=[],
        origin_ip_result={"malicious": False},
    )

    # Email type now reflects INTENT (subject keyword) — not the threat.
    # Threat is expressed through risk/verdict, not email_type.
    assert result["email_type"] == "Account Security"
    assert result["risk"] in {"suspicious", "malicious"}


def test_classify_benign_email_type_from_subject():
    result = calculate_risk_profile(
        headers={"subject": "Weekly newsletter: this week in product updates"},
        spf={"result": "pass"},
        dkim={"signature_present": True, "valid": True},
        dmarc={"record_found": True, "policy": "quarantine"},
        homograph_result={"suspicious": False},
        urls=[],
        attachments=[],
        origin_ip_result={"malicious": False},
    )

    # "Newsletter" subject keyword maps to "Marketing" in the new classification
    assert result["email_type"] == "Marketing"
    assert result["risk"] == "clean"
    assert result["threat_level"] == "Low"
