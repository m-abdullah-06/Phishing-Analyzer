from verdict_engine import classify_email_type, determine_final_verdict, calculate_risk_profile, determine_risk_band
from main import build_mitre_mapping, format_auth_summary


def test_build_mitre_mapping_for_clean_email_returns_no_phishing_techniques():
    techniques = build_mitre_mapping([], [], {"suspicious": False}, [])
    assert techniques == []


def test_build_mitre_mapping_ignores_plain_url_without_suspicious_signal():
    techniques = build_mitre_mapping([{"url": "https://example.com/login"}], [], {"suspicious": False}, [])
    assert techniques == []


def test_build_mitre_mapping_for_impersonation_only_maps_t1656():
    techniques = build_mitre_mapping([], [], {"suspicious": True}, ["display_name_impersonation"])
    ids = {item["id"] for item in techniques}
    assert "T1656" in ids
    assert "T1566" not in ids
    assert any("display_name_impersonation" in item.get("evidence", []) for item in techniques if item["id"] == "T1656")


def test_build_mitre_mapping_for_url_based_phishing_maps_t1566_and_t1566_002():
    techniques = build_mitre_mapping([{"url": "https://example.com/login"}], [], {"suspicious": False}, ["suspicious_url"])
    ids = {item["id"] for item in techniques}
    assert "T1566" in ids
    assert "T1566.002" in ids
    assert "T1204.001" in ids
    assert any("suspicious_url" in item.get("evidence", []) for item in techniques if item["id"] == "T1566.002")


def test_build_mitre_mapping_for_attachment_phishing_maps_t1566_001_when_justified():
    techniques = build_mitre_mapping([], [{"filename": "invoice.pdf", "dangerous_extension": True}], {"suspicious": False}, ["suspicious_attachment"])
    ids = {item["id"] for item in techniques}
    assert "T1566" in ids
    assert "T1566.001" in ids
    assert "T1204.002" in ids
    assert any("suspicious_attachment" in item.get("evidence", []) for item in techniques if item["id"] == "T1566.001")


def test_format_auth_summary_omits_none_zero_risk_auth():
    summary = format_auth_summary(
        {"result": "none", "impact": {"risk_contribution": 0}},
        {"valid": None, "impact": {"risk_contribution": 0}},
        {"policy": None, "impact": {"risk_contribution": 0}},
    )
    assert "SPF" in summary
    assert "No SPF risk contribution" in summary
    assert "risk factor" not in summary.lower()


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


def test_classify_email_type_uses_known_mime_when_subject_missing():
    result = classify_email_type(
        headers={"subject": "", "from": ""},
        spf={"result": "pass"},
        dkim={"valid": True},
        dmarc={"policy": "quarantine"},
        homograph_result={"suspicious": False},
        urls=[],
        attachments=[],
        origin_ip_result={"malicious": False},
        mime_analysis={"content_type": "text/plain", "anomalies": []},
    )
    assert result == "text/plain"


def test_classify_email_type_detects_multipart_mixed_before_unknown():
    result = classify_email_type(
        headers={"subject": "", "from": ""},
        spf={"result": "pass"},
        dkim={"valid": True},
        dmarc={"policy": "quarantine"},
        homograph_result={"suspicious": False},
        urls=[],
        attachments=[],
        origin_ip_result={"malicious": False},
        mime_analysis={"content_type": "multipart/mixed", "anomalies": []},
    )
    assert result == "multipart/mixed"
