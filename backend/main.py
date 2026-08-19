from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
import os
from groq import Groq
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

import email_parser
import auth_checker
import homograph
import sender_analysis
import content_analysis
import threat_intel
import verdict_engine

app = FastAPI(title="Phishing Email Analyzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


def build_mitre_mapping(urls, attachments, homograph_result, signals):
    techniques = [{"id": "T1566", "name": "Phishing"}]
    
    if urls:
        # Check if URL is suspicious or malicious based on the verdict signals
        has_bad_url = any("suspicious_url" in s or "malicious_url" in s or "credential_harvesting" in s for s in signals)
        if has_bad_url:
            techniques.append({"id": "T1566.002", "name": "Spearphishing Link"})
            techniques.append({"id": "T1204.001", "name": "User Execution: Malicious Link"})
            
    if attachments:
        has_bad_attachment = any("suspicious_attachment" in s or "malicious_attachment" in s for s in signals)
        if has_bad_attachment:
            techniques.append({"id": "T1566.001", "name": "Spearphishing Attachment"})
            techniques.append({"id": "T1204.002", "name": "User Execution: Malicious File"})
            
    if homograph_result.get("suspicious") or any("spoof" in s for s in signals) or any("impersonation" in s for s in signals):
        techniques.append({"id": "T1656", "name": "Impersonation"})
        
    return techniques


def get_ai_summary(headers, spf, dkim, dmarc, sender_identity, homograph_result, urls, attachments, verdict_profile, mime_analysis=None) -> str:
    final_risk = verdict_profile["risk"]
    final_score = verdict_profile["score"]
    final_confidence = verdict_profile["confidence"]
    email_type = verdict_profile["email_type"]
    threat_level = verdict_profile["threat_level"]
    signals = verdict_profile.get("signals", [])          # list of signal name strings
    signal_breakdown = verdict_profile.get("signal_breakdown", [])  # list of {signal, weight} dicts

    CRITICAL_SIGNAL_NAMES = {
        "confirmed_malicious_url",
        "known_malicious_attachment_hash",
        "credential_harvesting_language",
        "display_name_impersonation",
        "content_high_pressure_credential_request",
    }

    if not groq_client:
        return (
            f"Deterministic verdict: {final_risk} ({final_score}/100, confidence {final_confidence}%). "
            f"Email type: {email_type}; threat level: {threat_level}. Manual review recommended. (Set GROQ_API_KEY for AI explanations.)"
        )

    # Build URL signal summaries (only include what was actually measured)
    url_signals = []
    for u in urls[:10]:
        vt_mal = u.get("vt_malicious")
        vt_tot = u.get("vt_total")
        if vt_mal is not None and vt_tot is not None:
            url_signals.append(f"{u['url'][:60]} — VT: {vt_mal}/{vt_tot} malicious")

    # Build attachment signal summaries
    attachment_signals = []
    for a in attachments:
        vt_mal = a.get("vt_malicious")
        vt_tot = a.get("vt_total")
        mb_found = a.get("mb_found")
        parts = []
        if vt_mal is not None and vt_tot is not None:
            parts.append(f"VT: {vt_mal}/{vt_tot} malicious")
        if mb_found:
            family = a.get("mb_family") or "unknown family"
            parts.append(f"MalwareBazaar hit ({family})")
        if parts:
            attachment_signals.append(f"{a.get('filename', 'unnamed')} — {', '.join(parts)}")

    # Build MIME anomaly list from the actual mime_analysis result (not verdict_profile)
    mime_anomalies = (mime_analysis or {}).get("anomalies", [])

    # Structured evidence block (mirrors spec format)
    structured_evidence = {
        "email_type": email_type,
        "risk_score": final_score,
        "confidence": final_confidence,
        "verdict": final_risk,
        "authentication": {
            "spf": spf.get("result", "UNKNOWN"),
            "dkim": "PASS" if dkim.get("valid") else ("FAIL" if dkim.get("checked") else "NONE"),
            "dmarc": dmarc.get("policy", "NONE"),
        },
        "url_signals": url_signals,
        "attachment_signals": attachment_signals,
        "mime_anomalies": mime_anomalies,
        "critical_indicators": [s for s in signals if s in CRITICAL_SIGNAL_NAMES],
        "spoofing_flags": headers.get("spoofing_flags", []),
        "sender_findings": [f["detail"] for f in sender_identity.get("findings", [])],
        "homograph": homograph_result.get("detail") if homograph_result.get("suspicious") else None,
    }

    import json
    evidence_json = json.dumps(structured_evidence, indent=2)

    SYSTEM_PROMPT = """\
You are a SOC analyst assistant. Your role is to explain the technical evidence in a structured email security verdict.

STRICT RULES — violating any of these is a critical error:
1. NEVER invent or assume authentication results not present in the evidence.
2. NEVER invent URL reputation, VT scores, or IP reputation data.
3. NEVER call something malicious unless there is explicit supporting evidence in the evidence block.
4. NEVER treat missing authentication (SPF/DKIM/DMARC = NONE or UNKNOWN) as proof of phishing.
5. NEVER modify, override, or contradict the risk_score, confidence, or verdict fields — they are system-determined.
6. If evidence is absent or inconclusive, explicitly acknowledge the uncertainty.
7. Clearly distinguish between observed evidence and your inferences.
8. Lead with the strongest signals first.
9. Use plain English. Write 3–5 sentences maximum.
10. End with exactly one concrete, actionable recommendation for the recipient or analyst."""

    USER_PROMPT = f"""\
Explain the following email security analysis result. Base your explanation strictly on the evidence provided.

Evidence:
{evidence_json}

Do not restate all fields. Focus on the signals that most strongly support the verdict and acknowledge any gaps."""

    try:
        response = groq_client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": USER_PROMPT},
            ],
            max_tokens=1024,
            temperature=0.2,  # Low temperature for factual, consistent output
        )
        content = response.choices[0].message.content
        if not content or not content.strip():
            raise ValueError("Model returned empty content (possibly filtered)")
        return content.strip()
    except Exception:
        # Fallback: deterministic narrative, no hallucination possible
        auth_summary = (
            f"SPF={spf.get('result', 'UNKNOWN')}, "
            f"DKIM={'PASS' if dkim.get('valid') else 'FAIL/NONE'}, "
            f"DMARC={dmarc.get('policy', 'NONE')}"
        )
        critical = structured_evidence["critical_indicators"]
        critical_str = ("; ".join(critical[:3])) if critical else "no critical indicators detected"
        return (
            f"Deterministic verdict: {final_risk} (score {final_score}/100, confidence {final_confidence}%). "
            f"Authentication: {auth_summary}. "
            f"Key indicators: {critical_str}. "
            f"Email classified as {email_type} with {threat_level} threat level."
        )


@app.post("/api/analyze")
async def analyze_email(
    file: UploadFile = File(None),
    raw_email: str = Form(None),
):
    if file:
        raw_bytes = await file.read()
    elif raw_email:
        raw_bytes = raw_email.encode('utf-8')
    else:
        raise HTTPException(status_code=400, detail="Provide either a .eml file or raw email text.")

    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty email content.")

    msg = email_parser.parse_raw_email(raw_bytes)
    headers = email_parser.get_header_summary(msg)
    mime_analysis = email_parser.analyze_mime(msg, raw_bytes)
    received_chain, origin_ip = email_parser.extract_received_chain(msg)
    urls = email_parser.extract_urls(msg)
    attachments = email_parser.extract_attachments(msg)

    from_domain = headers["from"]["domain"]

    # Auth checks — these do blocking DNS/crypto calls, run off the event loop
    spf_domain = headers["return_path"]["domain"] if headers["return_path"] else from_domain
    spf = await run_in_threadpool(auth_checker.check_spf, spf_domain, origin_ip, from_domain)
    dkim_result = await run_in_threadpool(auth_checker.check_dkim, raw_bytes, from_domain)
    dmarc_result = await run_in_threadpool(auth_checker.check_dmarc, from_domain, spf, dkim_result)

    homograph_result = homograph.check_homograph(from_domain)
    sender_identity = sender_analysis.analyze_sender_identity(headers)
    content_result = content_analysis.analyze_content(headers.get("subject"), email_parser.get_message_text(msg), sender_identity)

    # Enrich URLs (cap at 10 unique domains to keep response time reasonable)
    for url_entry in urls[:10]:
        vt_data = await threat_intel.check_vt_domain(url_entry["domain"])
        stats = threat_intel.parse_vt_stats(vt_data)
        url_entry["vt_malicious"] = stats["malicious"]
        url_entry["vt_total"] = stats["total"]

    esp_result = content_analysis.analyze_esp(
        msg, urls, {"spf": spf, "dkim": dkim_result, "dmarc": dmarc_result}, sender_identity, content_result, mime_analysis
    )

    # Enrich attachments
    for attachment in attachments:
        vt_data = await threat_intel.check_vt_hash(attachment["sha256"])
        stats = threat_intel.parse_vt_stats(vt_data)
        attachment["vt_malicious"] = stats["malicious"]
        attachment["vt_total"] = stats["total"]

        mb_data = await threat_intel.check_malwarebazaar(attachment["sha256"])
        mb_found = mb_data.get("query_status") == "ok"
        mb_family = None
        if mb_found:
            try:
                mb_family = mb_data.get("data", [{}])[0].get("signature")
            except Exception:
                pass
        attachment["mb_found"] = mb_found
        attachment["mb_family"] = mb_family

    # Enrich origin IP
    origin_ip_result = {"ip": origin_ip, "malicious": False, "vt_malicious": 0, "abuse_confidence": 0}
    if origin_ip:
        vt_data = await threat_intel.check_vt_ip(origin_ip)
        stats = threat_intel.parse_vt_stats(vt_data)
        abuse_data = await threat_intel.check_abuseipdb(origin_ip)
        abuse_confidence = 0
        try:
            abuse_confidence = abuse_data.get("data", {}).get("abuseConfidenceScore", 0)
        except Exception:
            pass
        origin_ip_result["vt_malicious"] = stats["malicious"]
        origin_ip_result["abuse_confidence"] = abuse_confidence
        origin_ip_result["malicious"] = stats["malicious"] > 0 or abuse_confidence >= 50

    verdict_profile = verdict_engine.calculate_risk_profile(
        headers, spf, dkim_result, dmarc_result, homograph_result, urls, attachments, origin_ip_result, sender_identity, mime_analysis, content_result, esp_result
    )

    risk_score = verdict_profile["score"]
    risk = verdict_profile["risk"]
    confidence = verdict_profile["confidence"]
    email_type = verdict_profile["email_type"]
    threat_level = verdict_profile["threat_level"]
    confidence_reason = verdict_profile.get("confidence_reason")

    mitre = build_mitre_mapping(urls, attachments, homograph_result, verdict_profile.get("signals", []))

    ai_summary = get_ai_summary(
        headers, spf, dkim_result, dmarc_result, sender_identity, homograph_result, urls, attachments, verdict_profile, mime_analysis
    )

    return {
        "email_type": email_type,
        "risk_score": risk_score,
        "risk": risk,
        "confidence": confidence,
        "confidence_reason": confidence_reason,
        "threat_level": threat_level,
        "final_verdict": risk,
        "ai_summary": ai_summary,
        "ai_explanation": ai_summary,
        "deterministic_verdict": {
            "score": risk_score,
            "risk": risk,
            "confidence": confidence,
            "confidence_reason": confidence_reason,
            "email_type": email_type,
            "threat_level": threat_level,
            "signals": verdict_profile.get("signals", []),
            "signal_breakdown": verdict_profile.get("signal_breakdown", []),
        },
        "signal_breakdown": verdict_profile.get("signal_breakdown", []),
        "headers": headers,
        "authentication": {"spf": spf, "dkim": dkim_result, "dmarc": dmarc_result},
        "sender_identity": sender_identity,
        "mime_analysis": mime_analysis,
        "content_analysis": content_result,
        "esp_analysis": esp_result,
        "homograph": homograph_result,
        "urls": urls,
        "attachments": attachments,
        "received_chain": received_chain,
        "origin_ip": origin_ip_result,
        "mitre_attack": mitre,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
