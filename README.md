# Phishing Email Analyzer

Upload a raw `.eml` file or paste raw email source. Get real SPF/DKIM/DMARC
verification, sender spoofing detection, homograph/typosquat detection,
IOC enrichment (URLs, attachments, origin IP), and a copy-paste-ready
incident report — mapped to MITRE ATT&CK.

Built as an advanced portfolio project, since phishing accounts for the
majority of L1 SOC tickets.

---

## What Makes This "Advanced"

Most beginner phishing tools just read the `Authentication-Results` header
the mail server already computed — which is trusting the messenger to grade
its own homework. This tool does the actual verification itself:

- **SPF** — real DNS TXT lookup, parses `ip4`/`ip6`/`include` mechanisms, and
  checks the originating IP (extracted from the `Received` chain) directly
  against the authorized ranges.
- **DKIM** — full cryptographic signature verification using `dkimpy`,
  pulling the sender's actual public key from DNS and checking the message
  wasn't tampered with after signing.
- **DMARC** — DNS lookup of the `_dmarc` record and policy parsing
  (`none` / `quarantine` / `reject`).
- **Homograph detection** — Levenshtein distance + character-substitution
  checks against a list of commonly spoofed brands, plus punycode (IDN)
  detection.
- **Attachment hashing** — SHA256 of every attachment, checked against
  VirusTotal and MalwareBazaar, flagged for dangerous extensions.
- **Received chain parsing** — reconstructs the hop-by-hop path and
  identifies the likely originating IP, then enriches it via VirusTotal
  and AbuseIPDB.

Known simplifications are documented directly in the code comments
(`auth_checker.py`) — SPF `include:` mechanisms aren't recursively resolved,
and DMARC organizational domain lookup is simplified without a full Public
Suffix List. Worth knowing, not something to hide.

---

## Stack

| Layer | Tech |
|---|---|
| Backend | Python + FastAPI |
| Email parsing | Python's built-in `email` module + BeautifulSoup |
| Auth verification | `dnspython`, `dkimpy` |
| Frontend | Next.js + TypeScript |
| AI Summary | Groq (llama-3.1-8b-instant) |
| Threat Intel | VirusTotal, AbuseIPDB, MalwareBazaar |

---

## Setup

### 1. Backend
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# Fill in your API keys
uvicorn main:app --reload --port 8000
```

### 2. Frontend
```bash
cd frontend
npm install
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
npm run dev
```

Open http://localhost:3000

### 3. Test it
A sample phishing `.eml` is included at the project root:
`sample-phishing-email.eml` — a fabricated PayPal-spoofing example with
mismatched Reply-To/Return-Path domains, a bit.ly link, and a fake `.exe`
attachment. Upload it to see the full pipeline run end to end.

---

## API Keys Needed

- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- MalwareBazaar (Auth-Key required as of 2025): https://auth.abuse.ch
- Groq: https://console.groq.com

---

## MITRE ATT&CK Techniques Mapped

| ID | Name | Triggered when |
|---|---|---|
| T1566 | Phishing | Always (base technique) |
| T1566.001 | Spearphishing Attachment | Attachment present |
| T1566.002 | Spearphishing Link | URL(s) present |
| T1204.001 | User Execution: Malicious Link | URL(s) present |
| T1204.002 | User Execution: Malicious File | Attachment present |
| T1656 | Impersonation | Homograph/spoofing detected |

---

## Author

Muhammad Abdullah — [github.com/m-abdullah-06](https://github.com/m-abdullah-06)
