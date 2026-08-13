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
import threat_intel

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


def calculate_risk(headers, spf, dkim, dmarc, homograph_result, urls, attachments, origin_ip_result):
    score = 0

    if headers["spoofing_flags"]:
        score += min(15 * len(headers["spoofing_flags"]), 25)

    if spf.get("result") == "fail":
        score += 15
    elif spf.get("result") == "softfail":
        score += 8
    elif spf.get("result") == "none":
        score += 10

    if dkim.get("signature_present") is False:
        score += 8
    elif dkim.get("valid") is False:
        score += 20

    if dmarc.get("record_found") and dmarc.get("policy") == "reject":
        pass  # strong legit policy, no penalty
    elif not dmarc.get("record_found"):
        score += 5

    if homograph_result.get("suspicious"):
        score += 20

    malicious_urls = [u for u in urls if u.get("vt_malicious", 0) and u["vt_malicious"] > 0]
    if malicious_urls:
        score += min(20 * len(malicious_urls), 30)
    elif any(u["suspicious_tld"] or u["is_shortener"] for u in urls):
        score += 8

    dangerous_attachments = [a for a in attachments if a.get("dangerous_extension") or a.get("vt_malicious", 0)]
    if dangerous_attachments:
        score += 30

    if origin_ip_result.get("malicious"):
        score += 15

    score = min(score, 100)

    if score >= 70:
        risk = "malicious"
    elif score >= 30:
        risk = "suspicious"
    else:
        risk = "clean"

    return score, risk


def build_mitre_mapping(urls, attachments, homograph_result):
    techniques = [{"id": "T1566", "name": "Phishing"}]
    if urls:
        techniques.append({"id": "T1566.002", "name": "Spearphishing Link"})
        techniques.append({"id": "T1204.001", "name": "User Execution: Malicious Link"})
    if attachments:
        techniques.append({"id": "T1566.001", "name": "Spearphishing Attachment"})
        techniques.append({"id": "T1204.002", "name": "User Execution: Malicious File"})
    if homograph_result.get("suspicious"):
        techniques.append({"id": "T1656", "name": "Impersonation"})
    return techniques


def get_ai_summary(headers, spf, dkim, dmarc, homograph_result, urls, attachments, risk, score) -> str:
    if not groq_client:
        return f"Risk assessed as {risk} ({score}/100). Manual review recommended. (Set GROQ_API_KEY for AI summaries.)"

    context = f"""
Subject: {headers['subject']}
From: {headers['from']['display_name']} <{headers['from']['email']}>
Spoofing flags: {'; '.join(headers['spoofing_flags']) if headers['spoofing_flags'] else 'None'}
SPF: {spf.get('result')} — {spf.get('detail')}
DKIM: {'valid' if dkim.get('valid') else 'invalid/missing'} — {dkim.get('detail')}
DMARC: policy={dmarc.get('policy')} — {dmarc.get('detail')}
Homograph check: {'SUSPICIOUS - ' + str(homograph_result.get('detail')) if homograph_result.get('suspicious') else 'clean'}
URLs found: {len(urls)}
Attachments found: {len(attachments)}
Risk score: {score}/100 ({risk})
"""

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": "You are a SOC analyst assistant reviewing a phishing alert. Given the "
                               "technical findings, write a 3-4 sentence analyst summary in plain English. "
                               "State the verdict and one clear recommended action (quarantine, block sender, "
                               "block URLs, notify user, or no action). No fluff, no markdown formatting.",
                },
                {"role": "user", "content": context},
            ],
            max_tokens=200,
        )
        return response.choices[0].message.content
    except Exception:
        return f"Risk assessed as {risk} ({score}/100). Manual review recommended."


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
    received_chain, origin_ip = email_parser.extract_received_chain(msg)
    urls = email_parser.extract_urls(msg)
    attachments = email_parser.extract_attachments(msg)

    from_domain = headers["from"]["domain"]

    # Auth checks — these do blocking DNS/crypto calls, run off the event loop
    spf_domain = headers["return_path"]["domain"] if headers["return_path"] else from_domain
    spf = await run_in_threadpool(auth_checker.check_spf, spf_domain, origin_ip)
    dkim_result = await run_in_threadpool(auth_checker.check_dkim, raw_bytes, from_domain)
    dmarc_result = await run_in_threadpool(auth_checker.check_dmarc, from_domain)

    homograph_result = homograph.check_homograph(from_domain)

    # Enrich URLs (cap at 10 unique domains to keep response time reasonable)
    for url_entry in urls[:10]:
        vt_data = await threat_intel.check_vt_domain(url_entry["domain"])
        stats = threat_intel.parse_vt_stats(vt_data)
        url_entry["vt_malicious"] = stats["malicious"]
        url_entry["vt_total"] = stats["total"]

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

    risk_score, risk = calculate_risk(
        headers, spf, dkim_result, dmarc_result, homograph_result, urls, attachments, origin_ip_result
    )

    mitre = build_mitre_mapping(urls, attachments, homograph_result)

    ai_summary = get_ai_summary(
        headers, spf, dkim_result, dmarc_result, homograph_result, urls, attachments, risk, risk_score
    )

    return {
        "risk_score": risk_score,
        "risk": risk,
        "ai_summary": ai_summary,
        "headers": headers,
        "authentication": {"spf": spf, "dkim": dkim_result, "dmarc": dmarc_result},
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
