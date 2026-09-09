<div align="center">
  <img src="frontend/public/favicon.png" alt="PhishScan Logo" width="120" />

  # PhishScan v2.0
  **Enterprise-Grade Email Forensics & Threat Intelligence**

  [![Next.js](https://img.shields.io/badge/Next.js-14-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
  [![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
  [![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python)](https://python.org)
  [![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)

  *Automated email analysis designed for Tier-1 SOC analysts, mimicking the depth of manual forensics with the speed of AI.*
</div>

---

## ⚡ Overview

Phishing accounts for the majority of initial access vectors and L1 SOC alerts. **PhishScan** is a purpose-built incident response tool that unpacks `.eml` files or raw email sources to perform deep forensic analysis. 

Instead of relying on pre-computed headers left by intermediary mail servers, PhishScan performs **real-time cryptographic validation** and dynamic threat intelligence enrichment. It outputs a comprehensive, copy-paste-ready incident report mapped directly to the **MITRE ATT&CK** framework.

### 🛡️ Why PhishScan?
Most basic phishing tools just read the `Authentication-Results` header — which is trusting the messenger to grade its own homework. PhishScan does the heavy lifting:
- **True Cryptographic DKIM Validation:** Pulls the sender's actual public key from DNS and verifies the cryptographic signature directly using `dkimpy`.
- **Direct SPF & DMARC Resolution:** Performs live DNS TXT lookups, parsing `ip4`/`ip6`/`include` mechanisms against the true originating IP extracted from the `Received` chain.
- **Evidence-Completeness Engine:** Employs a deterministic risk-scoring engine that strictly decouples *email intent* (e.g., Marketing, Account Security) from *threat verdict*, ensuring objective analysis without AI hallucination.
- **Advanced UI:** A sleek, glassmorphic dark-mode dashboard providing immediate visibility into complex forensic data.

---

## 🚀 Core Features

- **Auth Verification Pipeline:** True validation of SPF, DKIM, and DMARC alignment.
- **Sender Identity & Spoofing:** Deep analysis of `From`, `Reply-To`, and `Return-Path` mismatches.
- **Homograph & Typosquat Detection:** Evaluates Levenshtein distance and character substitutions against major brands, combined with Punycode (IDN) detection.
- **Content & Intent Analysis:** Heuristic detection of high-pressure social engineering tactics, credential harvesting language, and structural MIME anomalies (e.g., evasion via malformed boundaries).
- **Automated IOC Enrichment:** 
  - **URLs:** Extraction, defanging, and reputation checks via **VirusTotal**.
  - **Attachments:** Static analysis (dangerous extensions, macros, nested archives) and SHA256 hashing checked against **VirusTotal** and **MalwareBazaar**.
  - **Infrastructure:** Originating IP extraction enriched via **AbuseIPDB**.
- **AI Analyst Summary:** Leverages Groq (Llama-3) to synthesize a concise, human-readable executive summary strictly grounded in the deterministic forensic evidence.

---

## 🏗️ Architecture Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Frontend** | Next.js 14, React, TypeScript | Premium glassmorphic UI, responsive grid layouts, built with Lucide icons. |
| **Backend** | Python, FastAPI | High-concurrency async API handling heavy DNS, crypto, and network I/O. |
| **Email Parsing** | `email` (Python), `BeautifulSoup` | Safe MIME traversal and payload extraction (no execution). |
| **Validation** | `dnspython`, `dkimpy` | Cryptographic signature verification and DNS resolution. |
| **AI Engine** | Groq (llama-3.1-8b) | High-speed LLM inference for evidence summarization. |
| **Threat Intel** | VT, AbuseIPDB, MalwareBazaar | API integrations for hash, URL, and IP reputation. |

---

## 🛠️ Installation & Setup

### 1. Backend Setup
Navigate to the backend directory and set up the Python environment:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Configure your environment variables:
```bash
cp .env.example .env
# Edit .env and insert your API keys
```

Start the FastAPI server:
```bash
uvicorn main:app --reload --port 8000
```

### 2. Frontend Setup
Navigate to the frontend directory:
```bash
cd frontend
npm install
```

Configure the API connection:
```bash
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
```

Start the Next.js development server:
```bash
npm run dev
```

Visit `http://localhost:3000` in your browser.

---

## 🔑 Required API Keys

To unlock the full potential of IOC enrichment and AI summarization, you will need the following free API keys:

- **VirusTotal:** [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
- **AbuseIPDB:** [abuseipdb.com/register](https://www.abuseipdb.com/register)
- **MalwareBazaar:** [auth.abuse.ch](https://auth.abuse.ch) *(Auth-Key required)*
- **Groq:** [console.groq.com](https://console.groq.com)

---

## 🗺️ MITRE ATT&CK Mapping

PhishScan automatically maps findings to the MITRE ATT&CK framework, aiding in standardized incident reporting:

| ID | Technique | Trigger Condition |
| :--- | :--- | :--- |
| **T1566** | Phishing | Base classification for malicious/suspicious emails |
| **T1566.001** | Spearphishing Attachment | Malicious or suspicious attachments identified |
| **T1566.002** | Spearphishing Link | Malicious or suspicious URLs extracted |
| **T1204.001** | User Execution: Malicious Link | Malicious URLs extracted |
| **T1204.002** | User Execution: Malicious File | Executable or malicious files attached |
| **T1656** | Impersonation | Homograph attacks or severe sender spoofing detected |

---

<div align="center">
  <p>Built by <strong>Muhammad Abdullah</strong> — <a href="https://github.com/m-abdullah-06">@m-abdullah-06</a></p>
  <p><em>Protecting inboxes, one header at a time.</em></p>
</div>
