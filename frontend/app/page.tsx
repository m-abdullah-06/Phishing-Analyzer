"use client"

import { useState, useRef } from 'react'
import RiskMeter from '@/components/RiskMeter'

interface AnalysisResult {
  risk_score: number
  risk: 'clean' | 'suspicious' | 'malicious'
  ai_summary: string
  headers: {
    from: { display_name: string | null; email: string | null; domain: string | null }
    reply_to: { display_name: string | null; email: string | null; domain: string | null } | null
    return_path: { display_name: string | null; email: string | null; domain: string | null } | null
    subject: string
    message_id: string
    date: string
    spoofing_flags: string[]
  }
  authentication: {
    spf: { record_found: boolean; result: string; detail: string }
    dkim: { signature_present: boolean; valid: boolean | null; domain: string | null; detail: string }
    dmarc: { record_found: boolean; policy: string | null; detail: string }
  }
  homograph: { suspicious: boolean; matched_brand: string | null; distance: number | null; detail: string | null }
  urls: { url: string; defanged: string; domain: string; is_shortener: boolean; suspicious_tld: boolean; vt_malicious?: number; vt_total?: number }[]
  attachments: { filename: string; sha256: string; extension: string; dangerous_extension: boolean; vt_malicious?: number; mb_found?: boolean; mb_family?: string | null }[]
  origin_ip: { ip: string | null; malicious: boolean; vt_malicious: number; abuse_confidence: number }
  mitre_attack: { id: string; name: string }[]
}

function AuthBadge({ label, status, detail }: { label: string; status: string; detail: string }) {
  const colorMap: Record<string, string> = {
    pass: 'var(--accent-emerald)', fail: 'var(--danger)', softfail: 'var(--accent-coral)',
    neutral: 'var(--accent-coral)', none: 'var(--text-muted)', unknown: 'var(--text-muted)',
  }
  const color = colorMap[status] || 'var(--text-muted)'
  return (
    <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 10, padding: '16px 18px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.1em' }}>{label}</span>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color,
          padding: '4px 10px', borderRadius: 6, border: `1px solid ${color}`, background: 'var(--surface-2)'
        }}>
          {status.toUpperCase()}
        </span>
      </div>
      <p style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.5 }}>{detail}</p>
    </div>
  )
}

export default function Home() {
  const [mode, setMode] = useState<'upload' | 'paste'>('upload')
  const [rawEmail, setRawEmail] = useState('')
  const [fileObj, setFileObj] = useState<File | null>(null)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const analyze = async () => {
    if (mode === 'upload' && !fileObj) return
    if (mode === 'paste' && !rawEmail.trim()) return

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const formData = new FormData()
      if (mode === 'upload' && fileObj) {
        formData.append('file', fileObj)
      } else {
        formData.append('raw_email', rawEmail)
      }

      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/analyze`, {
        method: 'POST',
        body: formData,
      })
      if (!res.ok) throw new Error('Analysis failed')
      const data = await res.json()
      setResult(data)
    } catch {
      setError('Failed to connect to backend. Make sure it is running on port 8000.')
    } finally {
      setLoading(false)
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) setFileObj(f)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    const f = e.dataTransfer.files?.[0]
    if (f) setFileObj(f)
  }

  const copyReport = () => {
    if (!result) return
    const lines = [
      '═══════════════════════════════════════════',
      '       PHISHING EMAIL — INCIDENT REPORT       ',
      '═══════════════════════════════════════════',
      '',
      '[ ALERT SUMMARY ]',
      `Subject     : ${result.headers.subject}`,
      `From        : ${result.headers.from.display_name || ''} <${result.headers.from.email}>`,
      `Verdict     : ${result.risk.toUpperCase()} (${result.risk_score}/100)`,
      '',
      '[ AI ANALYST SUMMARY ]',
      result.ai_summary,
      '',
      '[ HEADER ANALYSIS ]',
      ...(result.headers.spoofing_flags.length
        ? result.headers.spoofing_flags.map((f) => `⚠ ${f}`)
        : ['No From/Reply-To/Return-Path mismatches detected.']),
      '',
      '[ AUTHENTICATION RESULTS ]',
      `SPF   : ${result.authentication.spf.result.toUpperCase()} — ${result.authentication.spf.detail}`,
      `DKIM  : ${result.authentication.dkim.valid ? 'VALID' : result.authentication.dkim.signature_present ? 'INVALID' : 'MISSING'} — ${result.authentication.dkim.detail}`,
      `DMARC : ${(result.authentication.dmarc.policy || 'none').toUpperCase()} — ${result.authentication.dmarc.detail}`,
      '',
    ]

    if (result.homograph.suspicious) {
      lines.push('[ DOMAIN SPOOFING ]', `⚠ ${result.homograph.detail}`, '')
    }

    if (result.urls.length) {
      lines.push('[ URLS FOUND ]')
      result.urls.forEach((u) => {
        lines.push(`${u.defanged}  [VT: ${u.vt_malicious || 0}/${u.vt_total || 0}]${u.is_shortener ? ' [SHORTENER]' : ''}${u.suspicious_tld ? ' [SUSPICIOUS TLD]' : ''}`)
      })
      lines.push('')
    }

    if (result.attachments.length) {
      lines.push('[ ATTACHMENTS ]')
      result.attachments.forEach((a) => {
        lines.push(`${a.filename} — SHA256: ${a.sha256}`)
        lines.push(`  VT: ${a.vt_malicious || 0} malicious | MalwareBazaar: ${a.mb_found ? `FOUND (${a.mb_family})` : 'not found'}${a.dangerous_extension ? ' [DANGEROUS EXTENSION]' : ''}`)
      })
      lines.push('')
    }

    if (result.origin_ip.ip) {
      lines.push('[ ORIGIN IP ]', `${result.origin_ip.ip} — VT: ${result.origin_ip.vt_malicious} malicious, AbuseIPDB confidence: ${result.origin_ip.abuse_confidence}%`, '')
    }

    lines.push('[ MITRE ATT&CK MAPPING ]')
    result.mitre_attack.forEach((t) => lines.push(`${t.id} — ${t.name}`))
    lines.push('', '─ Generated by Phishing Email Analyzer | github.com/m-abdullah-06')

    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <main className="fade-up" style={{ minHeight: '100vh', background: 'var(--bg)', padding: '40px 20px 80px' }}>

      {/* Header */}
      <div style={{ maxWidth: 780, margin: '0 auto 40px', textAlign: 'center' }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 8,
          background: 'var(--accent-emerald-dim)', border: '1px solid rgba(18,184,134,0.08)', marginBottom: 20,
        }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-emerald)', boxShadow: '0 0 8px var(--accent-emerald)' }} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-emerald)', letterSpacing: '0.12em' }}>EMAIL FORENSICS</span>
        </div>
        <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(30px, 5.5vw, 48px)', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 12 }}>
          Phishing Email Analyzer
        </h1>
        <p style={{ color: 'var(--text-dim)', fontSize: 15, maxWidth: 520, margin: '0 auto' }}>
          Upload a raw .eml file or paste the source. Get real SPF/DKIM/DMARC verification, spoofing detection, IOC enrichment, and a ready-to-file incident report.
        </p>
      </div>

      {/* Mode toggle */}
      <div style={{ maxWidth: 780, margin: '0 auto 16px', display: 'flex', gap: 8, justifyContent: 'center' }}>
        {(['upload', 'paste'] as const).map((m) => (
          <button
            key={m}
            onClick={() => setMode(m)}
            style={{
              padding: '8px 20px', borderRadius: 8, cursor: 'pointer',
              background: mode === m ? 'var(--accent-emerald)' : 'var(--surface)',
              color: mode === m ? '#05131A' : 'var(--text-dim)',
              border: `1px solid ${mode === m ? 'var(--accent-emerald)' : 'var(--muted-border)'}`,
              fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600,
            }}
          >
            {m === 'upload' ? '📎 Upload .eml' : '📋 Paste Source'}
          </button>
        ))}
      </div>

      {/* Input area */}
      <div style={{ maxWidth: 780, margin: '0 auto 24px' }}>
        {mode === 'upload' ? (
          <div
            onDrop={handleDrop}
            onDragOver={(e) => e.preventDefault()}
            onClick={() => fileInputRef.current?.click()}
            style={{
              border: `2px dashed ${fileObj ? 'var(--accent-emerald)' : 'var(--muted-border)'}`,
              borderRadius: 12, padding: '40px 20px', textAlign: 'center', cursor: 'pointer',
              background: 'var(--surface)', transition: 'border-color 0.2s',
            }}
          >
            <input ref={fileInputRef} type="file" accept=".eml,.txt" onChange={handleFileChange} style={{ display: 'none' }} />
            {fileObj ? (
              <div>
                <div style={{ color: 'var(--accent-emerald)', fontFamily: 'var(--font-mono)', fontSize: 14, marginBottom: 4 }}>✓ {fileObj.name}</div>
                <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Click to choose a different file</div>
              </div>
            ) : (
              <div>
                <div style={{ fontSize: 32, marginBottom: 8 }}>📧</div>
                <div style={{ color: 'var(--text-dim)', fontSize: 14, marginBottom: 4 }}>Drop a .eml file here, or click to browse</div>
                <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Exported from Gmail, Outlook, or any mail client</div>
              </div>
            )}
          </div>
        ) : (
          <textarea
            value={rawEmail}
            onChange={(e) => setRawEmail(e.target.value)}
            placeholder={`Paste the full raw email source here, including headers:\n\nDelivered-To: victim@example.com\nReceived: from ...\nFrom: "PayPal Support" <support@paypal-secure.xyz>\nSubject: Your account has been suspended\n...`}
            style={{
              width: '100%', minHeight: 220, background: 'var(--surface)', border: '1px solid var(--muted-border)',
              borderRadius: 12, padding: 16, color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 12.5,
              resize: 'vertical', outline: 'none', lineHeight: 1.6,
            }}
          />
        )}

          <button
            onClick={analyze}
            disabled={loading || (mode === 'upload' ? !fileObj : !rawEmail.trim())}
            className="btn-cta"
            style={{
              width: '100%', marginTop: 12, padding: '14px', borderRadius: 12, border: 'none',
              background: loading || (mode === 'upload' ? !fileObj : !rawEmail.trim()) ? 'var(--surface-2)' : 'linear-gradient(90deg,var(--accent-emerald),var(--accent-coral))',
              color: loading || (mode === 'upload' ? !fileObj : !rawEmail.trim()) ? 'var(--text-muted)' : '#05131A',
              fontFamily: 'var(--font-display)', fontSize: 15, fontWeight: 700,
              cursor: loading ? 'not-allowed' : 'pointer', boxShadow: loading ? 'none' : '0 8px 30px rgba(18,184,134,0.12)'
            }}
          >
            {loading ? 'Analyzing...' : 'Analyze Email →'}
          </button>
      </div>

      {error && (
        <div style={{ maxWidth: 780, margin: '0 auto 24px', padding: '12px 16px', background: 'rgba(255,90,90,0.08)', border: '1px solid rgba(255,90,90,0.18)', borderRadius: 8, color: 'var(--danger)', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
          ⚠ {error}
        </div>
      )}

      {loading && (
        <div style={{ maxWidth: 780, margin: '0 auto', textAlign: 'center', padding: '32px 0' }}>
          <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
            <span style={{ color: 'var(--accent-emerald)' }}>▶</span> Parsing headers, verifying SPF/DKIM/DMARC, enriching IOCs...
          </div>
        </div>
      )}

      {result && !loading && (
        <div className="animate-in" style={{ maxWidth: 780, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Risk + AI Summary */}
          <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr', gap: 16 }}>
            <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: '28px 16px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <RiskMeter score={result.risk_score} risk={result.risk} />
            </div>
            <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: '20px 24px' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.12em', color: 'var(--accent-emerald)', background: 'var(--accent-emerald-dim)', padding: '2px 8px', borderRadius: 4 }}>AI SUMMARY</span>
              <p style={{ color: 'var(--text)', fontSize: 14, lineHeight: 1.7, fontStyle: 'italic', marginTop: 12 }}>{result.ai_summary}</p>
              <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--muted-border)' }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: 3 }}>SUBJECT</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12.5, color: 'var(--text)' }}>{result.headers.subject}</div>
              </div>
            </div>
          </div>

          {/* Header Analysis */}
          <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: 20 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: 14 }}>HEADER ANALYSIS</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontFamily: 'var(--font-mono)', fontSize: 12.5 }}>
              <div><span style={{ color: 'var(--text-muted)' }}>From:</span> {result.headers.from.display_name} &lt;{result.headers.from.email}&gt;</div>
              {result.headers.reply_to && <div><span style={{ color: 'var(--text-muted)' }}>Reply-To:</span> {result.headers.reply_to.email}</div>}
              {result.headers.return_path && <div><span style={{ color: 'var(--text-muted)' }}>Return-Path:</span> {result.headers.return_path.email}</div>}
            </div>
            {result.headers.spoofing_flags.length > 0 && (
              <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {result.headers.spoofing_flags.map((flag, i) => (
                  <div key={i} style={{ background: 'rgba(255,90,90,0.08)', border: '1px solid rgba(255,90,90,0.25)', borderRadius: 8, padding: '10px 12px', color: 'var(--danger)', fontSize: 12.5 }}>
                    ⚠ {flag}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Auth results */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
            <AuthBadge label="SPF" status={result.authentication.spf.result} detail={result.authentication.spf.detail} />
            <AuthBadge
              label="DKIM"
              status={result.authentication.dkim.valid ? 'pass' : result.authentication.dkim.signature_present ? 'fail' : 'none'}
              detail={result.authentication.dkim.detail}
            />
            <AuthBadge
              label="DMARC"
              status={result.authentication.dmarc.policy === 'reject' ? 'pass' : result.authentication.dmarc.record_found ? 'neutral' : 'none'}
              detail={result.authentication.dmarc.detail}
            />
          </div>

          {/* Homograph warning */}
          {result.homograph.suspicious && (
            <div style={{ background: 'rgba(255,90,90,0.08)', border: '1px solid rgba(255,90,90,0.3)', borderRadius: 12, padding: '16px 20px' }}>
              <div style={{ color: 'var(--danger)', fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.1em', marginBottom: 6 }}>⚠ DOMAIN SPOOFING DETECTED</div>
              <div style={{ color: 'var(--text)', fontSize: 13 }}>{result.homograph.detail}</div>
            </div>
          )}

          {/* URLs */}
          {result.urls.length > 0 && (
            <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: 20 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: 14 }}>URLS FOUND ({result.urls.length})</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {result.urls.map((u, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', background: 'var(--surface-2)', borderRadius: 6, gap: 8 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-dim)', wordBreak: 'break-all' }}>{u.defanged}</span>
                    <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                      {u.is_shortener && <Tag color="var(--accent-coral)">SHORTENER</Tag>}
                      {u.suspicious_tld && <Tag color="var(--accent-coral)">SUS TLD</Tag>}
                      {(u.vt_malicious || 0) > 0 && <Tag color="var(--danger)">{u.vt_malicious}/{u.vt_total} VT</Tag>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attachments */}
          {result.attachments.length > 0 && (
            <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: 20 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: 14 }}>ATTACHMENTS ({result.attachments.length})</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {result.attachments.map((a, i) => (
                  <div key={i} style={{ padding: '10px 12px', background: 'var(--surface-2)', borderRadius: 8 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text)' }}>{a.filename}</span>
                      {a.dangerous_extension && <Tag color="var(--danger)">DANGEROUS EXT</Tag>}
                    </div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10.5, color: 'var(--text-muted)', wordBreak: 'break-all' }}>{a.sha256}</div>
                    <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                      {(a.vt_malicious || 0) > 0 && <Tag color="var(--danger)">VT: {a.vt_malicious} malicious</Tag>}
                      {a.mb_found && <Tag color="var(--danger)">MalwareBazaar: {a.mb_family}</Tag>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Origin IP */}
          {result.origin_ip.ip && (
            <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: 20 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: 10 }}>ORIGIN IP</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 15, color: result.origin_ip.malicious ? 'var(--danger)' : 'var(--text)' }}>{result.origin_ip.ip}</span>
                <div style={{ display: 'flex', gap: 8 }}>
                  <Tag color={result.origin_ip.vt_malicious > 0 ? 'var(--danger)' : 'var(--text-muted)'}>VT: {result.origin_ip.vt_malicious}</Tag>
                  <Tag color={result.origin_ip.abuse_confidence >= 50 ? 'var(--danger)' : 'var(--text-muted)'}>Abuse: {result.origin_ip.abuse_confidence}%</Tag>
                </div>
              </div>
            </div>
          )}

          {/* MITRE */}
          <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em' }}>MITRE ATT&CK</span>
            {result.mitre_attack.map((t) => (
              <span key={t.id} style={{ padding: '3px 10px', borderRadius: 4, background: 'var(--surface-2)', border: '1px solid var(--muted-border)', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
                {t.id} · {t.name}
              </span>
            ))}
          </div>

          {/* Copy report */}
          <button
            onClick={copyReport}
            className="btn-cta"
            style={{
              padding: '12px', borderRadius: 10, background: 'transparent', border: '1px solid var(--muted-border)',
              color: copied ? 'var(--accent-emerald)' : 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12,
              cursor: 'pointer', letterSpacing: '0.08em',
            }}
          >
            {copied ? '✓ INCIDENT REPORT COPIED TO CLIPBOARD' : '⎘ COPY INCIDENT REPORT'}
          </button>
        </div>
      )}

      <div style={{ textAlign: 'center', marginTop: 64, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.08em' }}>
        built by <a href="https://github.com/m-abdullah-06" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-emerald)', textDecoration: 'none' }}>m-abdullah-06</a>
        {' '} · SPF/DKIM/DMARC · homograph detection · VirusTotal · AbuseIPDB · MalwareBazaar · Groq
      </div>
    </main>
  )
}

function Tag({ children, color }: { children: React.ReactNode; color: string }) {
  return (
    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, color, background: 'var(--surface-2)', padding: '4px 10px', borderRadius: 6, border: `1px solid ${color}`, whiteSpace: 'nowrap' }}>
      {children}
    </span>
  )
}
