"""Deterministic email verdict engine.

This module owns the final security decision. The model may explain the evidence,
but it never decides the verdict. The backend computes risk and confidence from
observable indicators and outputs a final verdict using fixed thresholds.
"""

SIGNAL_WEIGHTS = {
    "spf_fail": 10,
    "spf_softfail": 6,
    "spf_neutral": 2,
    "spf_unknown": 4,
    "dkim_fail": 10,
    "dkim_unknown": 4,
    "dmarc_fail": 12,
    "dmarc_unknown": 4,
    "from_replyto_mismatch": 8,
    "display_name_impersonation": 15,
    "suspicious_url": 15,
    "confirmed_malicious_url": 40,
    "url_domain_mismatch": 8,
    "credential_harvesting_language": 10,
    "suspicious_attachment": 20,
    "known_malicious_attachment_hash": 50,
    "mime_anomaly": 5,
    "known_trusted_sender": -10,
    "normal_unsubscribe_url": -2,
    "normal_esp_tracking_url": 0,
    "normal_newsletter_behavior": -3,
}


def _normalize_subject(subject: str) -> str:
    return (subject or "").strip().lower()


def determine_risk_band(score: int, critical_indicator: bool = False) -> str:
    if critical_indicator:
        if score >= 90:
            return "MALICIOUS"
        return "HIGH RISK"

    if score >= 90:
        return "MALICIOUS"
    if score >= 70:
        return "HIGH RISK"
    if score >= 50:
        return "SUSPICIOUS"
    if score >= 25:
        return "LOW RISK"
    return "CLEAN"


def determine_final_verdict(score: int, critical_indicator: bool = False) -> str:
    band = determine_risk_band(score, critical_indicator)
    if band == "MALICIOUS":
        return "malicious"
    if band in {"HIGH RISK", "SUSPICIOUS"}:
        return "suspicious"
    return "clean"


def determine_threat_level(score: int, critical_indicator: bool = False) -> str:
    band = determine_risk_band(score, critical_indicator)
    if band == "MALICIOUS":
        return "Critical"
    if band == "HIGH RISK":
        return "High"
    if band == "SUSPICIOUS":
        return "Moderate"
    return "Low"


def classify_email_type(headers, spf, dkim, dmarc, homograph_result, urls, attachments, origin_ip_result, sender_identity=None, content_analysis=None, esp_analysis=None) -> str:
    subject = _normalize_subject(headers.get("subject", ""))
    
    # Check ESP characteristics for marketing/newsletters
    if esp_analysis and esp_analysis.get("list_unsubscribe"):
        return "Marketing"

    if any(token in subject for token in ["invoice", "payment", "receipt", "billing", "order", "purchase"]):
        return "Transactional"
    if any(token in subject for token in ["newsletter", "weekly", "update", "unsubscribe", "promo", "sale", "digest"]):
        return "Marketing"
    if any(token in subject for token in ["password", "security alert", "verify account", "reset", "login", "account security", "action required"]):
        return "Account Security"
    if any(token in subject for token in ["internal", "employee", "hr", "benefits", "policy"]):
        return "Internal"
    if any(token in subject for token in ["notification", "welcome", "confirm", "approved", "alert"]):
        return "Notification"
    if any(token in subject for token in ["friend", "personal", "family", "private"]):
        return "Personal"
    if any(token in subject for token in ["malformed", "garbled", "invalid", "=?", "\ufffd"]):
        return "Malformed"
        
    # If there is basically no structure to indicate what it is
    if not subject and not headers.get("from"):
        return "Unknown"

    return "Unknown"


def _build_signal_breakdown(headers, spf, dkim, dmarc, homograph_result, urls, attachments, origin_ip_result, sender_identity=None, mime_analysis=None, content_analysis=None, esp_analysis=None):
    applied = []

    spoof_count = len(headers.get("spoofing_flags", []))
    if spoof_count:
        applied.append({"signal": "from_replyto_mismatch", "weight": SIGNAL_WEIGHTS["from_replyto_mismatch"], "applied": True})

    # Sender identity findings are independently explainable and deliberately
    # scored per finding, rather than collapsed into a generic header mismatch.
    for finding in (sender_identity or {}).get("findings", []):
        applied.append({
            "signal": f"sender_{finding.get('code', 'anomaly')}",
            "weight": finding.get("risk_contribution", 0),
            "applied": True,
        })

    # Authentication states and their scoring impact are deliberately separate.
    # NONE means no evidence/record, not a failed authentication attempt.
    auth_states = {
        "spf": (spf.get("state") or spf.get("result") or "unknown").lower(),
        "dkim": (dkim.get("state") or ("none" if dkim.get("signature_present") is False else "fail" if dkim.get("valid") is False else "pass" if dkim.get("valid") is True else "unknown")).lower(),
        "dmarc": (dmarc.get("state") or ("none" if dmarc.get("record_found") is False else "unknown")).lower(),
    }
    for mechanism, state in auth_states.items():
        if state == "none" or state == "pass":
            continue
        signal = f"{mechanism}_{state}"
        weight = (spf if mechanism == "spf" else dkim if mechanism == "dkim" else dmarc).get("impact", {}).get("risk_contribution")
        if weight is None:
            weight = SIGNAL_WEIGHTS.get(signal, 0)
        if weight:
            applied.append({"signal": signal, "weight": weight, "applied": True})

    if homograph_result.get("suspicious"):
        applied.append({"signal": "display_name_impersonation", "weight": SIGNAL_WEIGHTS["display_name_impersonation"], "applied": True})

    malicious_urls = [u for u in urls if u.get("vt_malicious", 0) > 0]
    if malicious_urls:
        applied.append({"signal": "confirmed_malicious_url", "weight": SIGNAL_WEIGHTS["confirmed_malicious_url"], "applied": True})
    elif any(u.get("suspicious_tld") or u.get("is_shortener") for u in urls):
        applied.append({"signal": "suspicious_url", "weight": SIGNAL_WEIGHTS["suspicious_url"], "applied": True})

    known_malicious_attachments = [a for a in attachments if a.get("vt_malicious", 0) > 0]
    static_risky_attachments = [a for a in attachments if a.get("dangerous_extension") or a.get("executable") or a.get("macro_enabled") or a.get("nested_archive") or a.get("suspicious_double_extension")]
    if known_malicious_attachments:
        applied.append({"signal": "known_malicious_attachment_hash", "weight": SIGNAL_WEIGHTS["known_malicious_attachment_hash"], "applied": True})
    elif static_risky_attachments:
        applied.append({"signal": "suspicious_attachment", "weight": SIGNAL_WEIGHTS["suspicious_attachment"], "applied": True})

    if (mime_analysis or {}).get("anomalies"):
        applied.append({"signal": "mime_anomaly", "weight": (mime_analysis or {}).get("risk_contribution", SIGNAL_WEIGHTS["mime_anomaly"]), "applied": True})

    if origin_ip_result.get("malicious"):
        applied.append({"signal": "url_domain_mismatch", "weight": SIGNAL_WEIGHTS["url_domain_mismatch"], "applied": True})

    for finding in (content_analysis or {}).get("findings", []):
        weight = finding.get("risk_contribution", 0)
        if weight:
            applied.append({"signal": f"content_{finding['type']}", "weight": weight, "applied": True})

    # ESP infrastructure is neutral by itself. Its small legitimacy credit is
    # available only when independently corroborated by authentication,
    # consistent identity, normal behavior, and mailing-list/message structure.
    if (esp_analysis or {}).get("strong_legitimacy"):
        applied.append({"signal": "corroborated_legitimate_esp", "weight": (esp_analysis or {}).get("risk_contribution", 0), "applied": True})

    return applied


def calculate_confidence(score, signal_breakdown, email_type, critical_indicator, parser_complete, reputation_coverage, conflicting_signals, malformed):
    confidence = 100

    if len(signal_breakdown) > 0:
        confidence += min(10, len(signal_breakdown) * 2)
    else:
        confidence -= 15

    if parser_complete:
        confidence += 8
    else:
        confidence -= 12

    if reputation_coverage:
        confidence += 8
    else:
        confidence -= 8

    if malformed:
        confidence -= 35
    if conflicting_signals:
        confidence -= 12
    if not parser_complete and not malformed:
        confidence -= 8

    if email_type in {"Phishing", "Malicious", "Spam"}:
        confidence += 6
    elif email_type in {"Unknown", "Malformed"}:
        confidence -= 12
    elif email_type in {"Transactional", "Newsletter", "Account Security", "Internal", "Notification", "Personal"}:
        confidence += 10

    if critical_indicator:
        confidence += 6
    if score >= 70:
        confidence += 6
    elif score <= 15:
        confidence += 8

    if malformed:
        confidence -= 20
    if not parser_complete:
        confidence -= 15
    if not reputation_coverage:
        confidence -= 10

    confidence = max(0, min(100, round(confidence)))
    return confidence


def calculate_risk_profile(headers, spf, dkim, dmarc, homograph_result, urls, attachments, origin_ip_result, sender_identity=None, mime_analysis=None, content_analysis=None, esp_analysis=None):
    signal_breakdown = _build_signal_breakdown(
        headers=headers,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        homograph_result=homograph_result,
        urls=urls,
        attachments=attachments,
        origin_ip_result=origin_ip_result,
        sender_identity=sender_identity,
        mime_analysis=mime_analysis,
        content_analysis=content_analysis,
        esp_analysis=esp_analysis,
    )

    critical_signals = {
        "confirmed_malicious_url",
        "known_malicious_attachment_hash",
        "credential_harvesting_language",
        "display_name_impersonation",
        "content_high_pressure_credential_request",
    }

    score = sum(item["weight"] for item in signal_breakdown)
    score = max(0, min(score, 100))
    critical_indicator = any(item["signal"] in critical_signals for item in signal_breakdown)
    parser_complete = bool(headers.get("subject") or headers.get("from") or urls or attachments or headers.get("spoofing_flags"))
    reputation_coverage = bool(urls or attachments or origin_ip_result.get("ip"))
    conflicting_signals = bool(
        (spf.get("result") == "pass" and dkim.get("valid") is False)
        or (spf.get("result") == "pass" and dmarc.get("policy") in {"none", None})
        or (homograph_result.get("suspicious") and len(urls) == 0)
    )
    has_from = bool(headers.get("from", {}).get("email"))
    malformed = bool(not headers.get("subject") and not has_from and not headers.get("message_id") and not urls and not attachments)

    risk_band = determine_risk_band(score, critical_indicator)
    risk = determine_final_verdict(score, critical_indicator)
    email_type = classify_email_type(
        headers=headers,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        homograph_result=homograph_result,
        urls=urls,
        attachments=attachments,
        origin_ip_result=origin_ip_result,
        sender_identity=sender_identity,
        content_analysis=content_analysis,
        esp_analysis=esp_analysis,
    )
    threat_level = determine_threat_level(score, critical_indicator)

    confidence = calculate_confidence(
        score=score,
        signal_breakdown=signal_breakdown,
        email_type=email_type,
        critical_indicator=critical_indicator,
        parser_complete=parser_complete,
        reputation_coverage=reputation_coverage,
        conflicting_signals=conflicting_signals,
        malformed=malformed,
    )

    # Inconclusive fallback logic (Rule 19)
    if (email_type in {"Unknown", "Malformed"} and confidence < 40) or malformed:
        risk = "inconclusive"
        threat_level = "Inconclusive"
        risk_band = "INCONCLUSIVE"
        
    confidence_reason = (
        "Insufficient evidence due to malformed MIME structure or parsing failure."
        if risk == "inconclusive" else
        "Sufficient structured evidence available for a stable assessment."
    )

    return {
        "score": score,
        "risk": risk,
        "risk_band": risk_band,
        "threat_level": threat_level,
        "confidence": confidence,
        "email_type": email_type,
        "critical_indicator": critical_indicator,
        "signals": [item["signal"] for item in signal_breakdown],
        "signal_breakdown": signal_breakdown,
        "confidence_reason": confidence_reason,
    }
