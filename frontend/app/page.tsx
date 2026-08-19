"use client"

import React, { useState, useRef } from 'react'
import {
  UploadCloud, FileText, ShieldAlert, ShieldCheck, Shield, AlertTriangle,
  Info, Activity, Search, Server, Link as LinkIcon, FileWarning, Fingerprint, Lock,
  ChevronRight, Copy, Check, ChevronDown, ChevronUp, CheckCircle2, XCircle, AlertCircle, FileKey, Target
} from 'lucide-react'

interface AnalysisResult {
  risk_score: number
  risk: 'clean' | 'suspicious' | 'malicious' | 'inconclusive'
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
    spf: AuthResult
    dkim: AuthResult & { signature_present: boolean; valid: boolean | null }
    dmarc: AuthResult & { policy: string | null }
  }
  sender_identity: SenderIdentity
  mime_analysis: MimeAnalysis
  content_analysis: ContentAnalysis
  esp_analysis: EspAnalysis
  homograph: { suspicious: boolean; matched_brand: string | null; distance: number | null; detail: string | null }
  urls: { url: string; defanged: string; domain: string; is_shortener: boolean; suspicious_tld: boolean; vt_malicious?: number; vt_total?: number }[]
  attachments: AttachmentAnalysis[]
  origin_ip: { ip: string | null; malicious: boolean; vt_malicious: number; abuse_confidence: number }
  mitre_attack: { id: string; name: string }[]
  signal_breakdown: { signal: string; weight: number; applied: boolean }[]
  email_type: string
  confidence: number
}

type AuthResult = {
  state: string
  result?: string
  domain?: string | null
  detail: string
  impact: { risk_contribution: number; label: string }
  alignment: { aligned: boolean; domain: string | null; from_domain?: string | null; reason: string }
}

type SenderAddress = { display_name: string | null; email: string | null; domain: string | null }
type SenderFinding = { code: string; severity: string; risk_contribution: number; detail: string; domain: string | null; brand: string | null }
type SenderIdentity = {
  display_name: string | null
  from: SenderAddress
  reply_to: SenderAddress | null
  return_path: SenderAddress | null
  findings: SenderFinding[]
  risk_contribution: number
  suspicious: boolean
}
type MimeAnalysis = { multipart: boolean; statuses: { status: 'ok' | 'warning'; message: string }[]; anomalies: string[]; risk_contribution: number; detail: string }
type AttachmentAnalysis = {
  filename: string; sha256: string; extension: string; mime_type: string; size_bytes: number
  dangerous_extension: boolean; archive: boolean; nested_archive: boolean; executable: boolean; macro_enabled: boolean; suspicious_double_extension: boolean
  vt_malicious?: number; mb_found?: boolean; mb_family?: string | null
}
type ContentAnalysis = { findings: { type: string; risk_contribution: number }[]; normal_patterns: string[]; risk_contribution: number; high_pressure_credential: boolean; assessment: string }
type EspAnalysis = { providers: string[]; tracking_url: boolean; list_unsubscribe: boolean; unsubscribe_url: boolean; multipart_html: boolean; auth_aligned: boolean; sender_consistent: boolean; normal_behavior: boolean; strong_legitimacy: boolean; risk_contribution: number; assessment: string; evidence: string[] }

const SIGNAL_DESCRIPTIONS: Record<string, string> = {
  "domain_spoofing": "The sender's domain visually mimics a known brand (homograph attack) to deceive the recipient.",
  "brand_impersonation": "The display name or sender address attempts to impersonate a known entity without authentication alignment.",
  "malicious_url": "One or more URLs in the email are flagged as malicious by threat intelligence feeds.",
  "suspicious_url": "URLs use suspicious TLDs, URL shorteners, or exhibit evasive characteristics.",
  "credential_harvesting": "The email content uses language strongly associated with credential theft (e.g., urgent password resets).",
  "malicious_attachment": "An attachment has a known malicious hash identified by threat intelligence.",
  "suspicious_attachment": "An attachment uses a dangerous extension, double extension, or contains macros/executables.",
  "mime_anomaly": "The email structure contains malformed MIME boundaries or evasion techniques.",
  "spf_fail": "The sender's IP is not authorized to send emails on behalf of the domain (SPF Hard Fail).",
  "dkim_fail": "The cryptographic signature of the email is invalid or has been tampered with.",
  "dmarc_fail": "The email fails DMARC alignment, meaning the visible sender does not match the authenticated identity.",
  "suspicious_origin_ip": "The originating IP has a poor reputation or is associated with spam/malware activity.",
  "high_pressure_tactic": "The email content creates a false sense of urgency or threatens negative consequences.",
  "freemail_sender": "The email originates from a free email provider (e.g., Gmail, Yahoo) but claims to be official.",
}

const getCategory = (signal: string) => {
  if (signal.includes('url')) return 'URL Analysis'
  if (signal.includes('attachment')) return 'Attachment Analysis'
  if (signal.includes('spf') || signal.includes('dkim') || signal.includes('dmarc')) return 'Authentication'
  if (signal.includes('spoofing') || signal.includes('impersonation') || signal.includes('sender')) return 'Sender Identity'
  if (signal.includes('mime')) return 'MIME Structure'
  if (signal.includes('ip')) return 'Infrastructure'
  return 'Content Analysis'
}

const getSeverity = (weight: number) => {
  if (weight >= 20) return { label: 'CRITICAL', color: 'var(--red)', bg: 'var(--red-dim)' }
  if (weight >= 10) return { label: 'HIGH', color: 'var(--amber)', bg: 'var(--amber-dim)' }
  if (weight >= 5) return { label: 'MEDIUM', color: 'var(--blue)', bg: 'var(--blue-dim)' }
  return { label: 'LOW', color: 'var(--green)', bg: 'var(--green-dim)' }
}

function RiskBreakdown({ signals }: { signals: { signal: string; weight: number; applied: boolean }[] }) {
  const active = signals.filter(s => s.weight !== 0)
  if (active.length === 0) return null

  const categories = active.reduce((acc, s) => {
    const cat = getCategory(s.signal)
    if (!acc[cat]) acc[cat] = { total: 0, items: [] }
    acc[cat].total += s.weight
    acc[cat].items.push(s)
    return acc
  }, {} as Record<string, { total: number; items: typeof signals }>)

  const totalScore = Object.values(categories).reduce((acc, cat) => acc + cat.total, 0)

  return (
    <div className="panel">
      <div className="row-between" style={{ marginBottom: 16 }}>
        <div className="row">
          <Activity size={14} color="var(--text-3)" />
          <span className="section-label">RISK BREAKDOWN</span>
        </div>
        <span className="mono" style={{ fontSize: 12, color: 'var(--text-2)' }}>+{totalScore} TOTAL RISK</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {Object.entries(categories).sort((a, b) => b[1].total - a[1].total).map(([cat, data]) => (
          <div key={cat} style={{ background: 'var(--surface-2)', padding: '12px 16px', borderRadius: 'var(--r-md)', border: '1px solid var(--border-dim)' }}>
            <div className="row-between">
              <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text)' }}>{cat}</span>
              <span className="mono" style={{ fontSize: 12, color: 'var(--red)', fontWeight: 600 }}>+{data.total}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 8, paddingTop: 8, borderTop: '1px solid var(--border)' }}>
              {data.items.map(s => (
                <div key={s.signal} className="row-between" style={{ paddingLeft: 8 }}>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-2)' }}>{s.signal.toUpperCase()}</span>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>+{s.weight}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function EvidenceFindings({ signals }: { signals: { signal: string; weight: number; applied: boolean }[] }) {
  const active = signals.filter(s => s.weight !== 0)
  if (active.length === 0) return null

  const sorted = [...active].sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))

  return (
    <div className="panel">
      <div className="row" style={{ marginBottom: 16 }}>
        <Target size={14} color="var(--text-3)" />
        <span className="section-label">EVIDENCE FINDINGS</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {sorted.map(s => {
          const sev = getSeverity(s.weight)
          const desc = SIGNAL_DESCRIPTIONS[s.signal] || `Signal: ${s.signal.replaceAll('_', ' ')}`
          return (
            <div key={s.signal} style={{ background: 'var(--surface-2)', borderRadius: 'var(--r-md)', border: '1px solid var(--border)', borderLeft: `3px solid ${sev.color}`, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px' }}>
                <div className="row-between" style={{ marginBottom: 8 }}>
                  <div className="row" style={{ gap: 12 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, color: sev.color, background: sev.bg, padding: '2px 6px', borderRadius: 4, letterSpacing: '0.05em' }}>
                      {sev.label}
                    </span>
                    <span className="mono" style={{ fontSize: 12, color: 'var(--text)' }}>{s.signal.toUpperCase()}</span>
                  </div>
                  <span className="mono" style={{ fontSize: 12, color: sev.color, fontWeight: 600 }}>+{s.weight}</span>
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-2)', lineHeight: 1.5 }}>
                  {desc}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function AuthBadge({ label, auth, icon: Icon }: { label: string; auth: AuthResult, icon: any }) {
  const status = (auth.state || auth.result || 'unknown').toLowerCase()
  let color = 'var(--text-3)'
  let bg = 'transparent'
  let IconStatus = AlertCircle

  if (status === 'pass') {
    color = 'var(--green)'
    bg = 'var(--green-dim)'
    IconStatus = CheckCircle2
  } else if (status === 'fail') {
    color = 'var(--red)'
    bg = 'var(--red-dim)'
    IconStatus = XCircle
  } else if (status === 'softfail' || status === 'neutral') {
    color = 'var(--amber)'
    bg = 'var(--amber-dim)'
    IconStatus = AlertTriangle
  }

  return (
    <div className="panel-tight" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="row-between">
        <div className="row" style={{ gap: 8 }}>
          <Icon size={16} color="var(--text-3)" />
          <span className="section-label">{label}</span>
        </div>
        <div className="row" style={{ background: bg, border: `1px solid ${color}`, padding: '2px 8px', borderRadius: 6, gap: 6 }}>
          <IconStatus size={12} color={color} />
          <span className="mono" style={{ fontSize: 11, fontWeight: 700, color }}>{status.toUpperCase()}</span>
        </div>
      </div>
      <p style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5 }}>{auth.detail}</p>
      <div style={{ paddingTop: 12, borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 10.5, color: 'var(--text-3)' }}>
        <div className="row-between"><span>RISK CONTRIBUTION</span><span style={{ color: auth.impact.risk_contribution > 0 ? 'var(--red)' : 'var(--green)' }}>+{auth.impact.risk_contribution}</span></div>
        <div className="row-between"><span>AUTH DOMAIN</span><span style={{ color: 'var(--text)' }}>{auth.alignment.domain || '—'}</span></div>
        <div className="row-between"><span>VISIBLE FROM</span><span style={{ color: 'var(--text)' }}>{auth.alignment.from_domain || '—'}</span></div>
        <div className="row-between">
          <span>ALIGNMENT</span>
          <span style={{ color: auth.alignment.aligned ? 'var(--green)' : 'var(--text-2)' }}>{auth.alignment.aligned ? 'ALIGNED' : 'NOT ALIGNED'}</span>
        </div>
      </div>
    </div>
  )
}

function Tag({ children, color, bg = 'var(--surface-2)' }: { children: React.ReactNode; color: string; bg?: string }) {
  return (
    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600, color, background: bg, padding: '3px 8px', borderRadius: 4, border: `1px solid ${color}40`, whiteSpace: 'nowrap' }}>
      {children}
    </span>
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
        ? result.headers.spoofing_flags.map((f) => `[WARNING] ${f}`)
        : ['No From/Reply-To/Return-Path mismatches detected.']),
      '',
      '[ SENDER IDENTITY ]',
      `Display Name: ${result.sender_identity.display_name || '—'}`,
      `From        : ${result.sender_identity.from.email || '—'}`,
      `Reply-To    : ${result.sender_identity.reply_to?.email || '—'}`,
      `Return-Path : ${result.sender_identity.return_path?.email || '—'}`,
      `Risk contribution: +${result.sender_identity.risk_contribution}`,
      ...(result.sender_identity.findings.length ? result.sender_identity.findings.map((finding) => `[WARNING] ${finding.detail} (+${finding.risk_contribution})`) : ['No sender-identity anomalies detected.']),
      '',
      '[ MIME STATUS ]',
      ...result.mime_analysis.statuses.map((status) => `${status.status === 'ok' ? '[OK]' : '[WARNING]'} ${status.message}`),
      `MIME Risk: +${result.mime_analysis.risk_contribution}`,
      result.mime_analysis.detail,
      '',
      '[ CONTENT ANALYSIS ]',
      `Risk contribution: +${result.content_analysis.risk_contribution}`,
      result.content_analysis.assessment,
      ...(result.content_analysis.findings.map((finding) => `${finding.type.replaceAll('_', ' ')}: +${finding.risk_contribution}`)),
      ...(result.content_analysis.normal_patterns.length ? [`Normal context: ${result.content_analysis.normal_patterns.join(', ')}`] : []),
      '',
      '[ LEGITIMATE ESP CONTEXT ]',
      result.esp_analysis.assessment,
      ...(result.esp_analysis.evidence.length ? result.esp_analysis.evidence : ['No corroborating ESP evidence.']),
      '',
      '[ AUTHENTICATION RESULTS ]',
      `SPF   : ${result.authentication.spf.state} · Risk contribution: +${result.authentication.spf.impact.risk_contribution} · ${result.authentication.spf.detail}`,
      `DKIM  : ${result.authentication.dkim.state} · Risk contribution: +${result.authentication.dkim.impact.risk_contribution} · ${result.authentication.dkim.detail}`,
      `DMARC : ${result.authentication.dmarc.state} · Risk contribution: +${result.authentication.dmarc.impact.risk_contribution} · ${result.authentication.dmarc.detail}`,
      `Alignment: From ${result.headers.from.domain || '—'} | SPF ${result.authentication.spf.alignment.domain || '—'} (${result.authentication.spf.alignment.aligned ? 'aligned' : 'not aligned'}) | DKIM ${result.authentication.dkim.alignment.domain || '—'} (${result.authentication.dkim.alignment.aligned ? 'aligned' : 'not aligned'})`,
      '',
    ]

    if (result.homograph.suspicious) {
      lines.push('[ DOMAIN SPOOFING ]', `[WARNING] ${result.homograph.detail}`, '')
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
        lines.push(`${a.filename} — ${a.mime_type} — ${a.size_bytes} bytes — SHA256: ${a.sha256}`)
        lines.push(`  VT: ${a.vt_malicious || 0} malicious | MalwareBazaar: ${a.mb_found ? `FOUND (${a.mb_family})` : 'not found'}${a.executable ? ' [EXECUTABLE]' : ''}${a.suspicious_double_extension ? ' [DOUBLE EXTENSION]' : ''}${a.macro_enabled ? ' [MACRO-ENABLED]' : ''}${a.archive ? ' [ARCHIVE]' : ''}${a.nested_archive ? ' [NESTED ARCHIVE]' : ''}`)
      })
      lines.push('')
    }

    if (result.origin_ip.ip) {
      lines.push('[ ORIGIN IP ]', `${result.origin_ip.ip} — VT: ${result.origin_ip.vt_malicious} malicious, AbuseIPDB confidence: ${result.origin_ip.abuse_confidence}%`, '')
    }

    lines.push('[ MITRE ATT&CK MAPPING ]')
    result.mitre_attack.forEach((t) => lines.push(`${t.id} — ${t.name}`))
    lines.push('', '─ Generated by PhishScan')

    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <main className="animate-in" style={{ paddingTop: 60 }}>
      {/* Header */}
      <div style={{ maxWidth: 680, margin: '0 auto 48px', textAlign: 'center' }}>
        <h1 style={{ fontSize: 'clamp(32px, 5vw, 44px)', fontWeight: 700, letterSpacing: '-0.03em', marginBottom: 16, color: 'var(--text)' }}>
          Analyze Suspicious Emails
        </h1>
        <p style={{ color: 'var(--text-2)', fontSize: 16, maxWidth: 540, margin: '0 auto' }}>
          Upload a raw .eml file or paste the source. Get enterprise-grade forensics, IOC enrichment, and automated incident reports.
        </p>
      </div>

      {/* Input Area */}
      <div style={{ maxWidth: 680, margin: '0 auto 40px' }}>
        <div style={{ display: 'flex', gap: 4, background: 'var(--surface)', padding: 6, borderRadius: 'var(--r-md)', border: '1px solid var(--border)', marginBottom: 16 }}>
          {(['upload', 'paste'] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              style={{
                flex: 1, padding: '10px', borderRadius: 'var(--r-sm)', border: 'none',
                background: mode === m ? 'var(--surface-3)' : 'transparent',
                color: mode === m ? 'var(--text)' : 'var(--text-3)',
                fontFamily: 'var(--font-sans)', fontSize: 13, fontWeight: 600,
                cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8
              }}
            >
              {m === 'upload' ? <UploadCloud size={16} /> : <FileText size={16} />}
              {m === 'upload' ? 'Upload .eml File' : 'Paste Raw Source'}
            </button>
          ))}
        </div>

        {mode === 'upload' ? (
          <div
            onDrop={handleDrop}
            onDragOver={(e) => e.preventDefault()}
            onClick={() => fileInputRef.current?.click()}
            style={{
              border: `1px dashed ${fileObj ? 'var(--green)' : 'var(--border)'}`,
              borderRadius: 'var(--r-lg)', padding: '60px 20px', textAlign: 'center',
              cursor: 'pointer', background: fileObj ? 'var(--green-dim)' : 'var(--surface)',
              transition: 'all 0.2s ease'
            }}
          >
            <input ref={fileInputRef} type="file" accept=".eml,.txt" onChange={handleFileChange} style={{ display: 'none' }} />
            {fileObj ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 48, height: 48, borderRadius: '50%', background: 'var(--green)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Check color="#000" size={24} />
                </div>
                <div>
                  <div className="mono" style={{ color: 'var(--green)', fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{fileObj.name}</div>
                  <div style={{ color: 'var(--text-3)', fontSize: 13 }}>Click or drag to replace</div>
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 48, height: 48, borderRadius: '50%', background: 'var(--surface-2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <UploadCloud color="var(--text-3)" size={24} />
                </div>
                <div>
                  <div style={{ color: 'var(--text)', fontSize: 15, fontWeight: 500, marginBottom: 4 }}>Select or drop a file</div>
                  <div style={{ color: 'var(--text-3)', fontSize: 13 }}>Supports .eml and .txt formats</div>
                </div>
              </div>
            )}
          </div>
        ) : (
          <textarea
            value={rawEmail}
            onChange={(e) => setRawEmail(e.target.value)}
            placeholder="Paste raw email headers and body here..."
            style={{
              width: '100%', height: 200, background: 'var(--surface)', border: '1px solid var(--border)',
              borderRadius: 'var(--r-lg)', padding: 16, color: 'var(--text)',
              fontFamily: 'var(--font-mono)', fontSize: 12, resize: 'vertical', outline: 'none'
            }}
          />
        )}

        <button
          onClick={analyze}
          disabled={loading || (mode === 'upload' ? !fileObj : !rawEmail.trim())}
          style={{
            width: '100%', marginTop: 16, padding: '14px', borderRadius: 'var(--r-md)', border: 'none',
            background: loading || (mode === 'upload' ? !fileObj : !rawEmail.trim()) ? 'var(--surface-2)' : 'var(--text)',
            color: loading || (mode === 'upload' ? !fileObj : !rawEmail.trim()) ? 'var(--text-3)' : '#000',
            fontFamily: 'var(--font-sans)', fontSize: 14, fontWeight: 600,
            cursor: loading ? 'not-allowed' : 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8
          }}
        >
          {loading ? <span className="spin"><Activity size={18} /></span> : <Shield size={18} />}
          {loading ? 'Analyzing Threat Indicators...' : 'Run Security Analysis'}
        </button>

        {error && (
          <div style={{ marginTop: 16, padding: '12px 16px', background: 'var(--red-dim)', border: '1px solid var(--red-border)', borderRadius: 'var(--r-md)', color: 'var(--red)', display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <AlertCircle size={16} />
            {error}
          </div>
        )}
      </div>

      {result && !loading && (
        <div className="animate-in" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Top Level Overview */}
          <div className="grid-2" style={{ gridTemplateColumns: 'minmax(280px, 1fr) 2fr' }}>
            
            {/* Verdict Card */}
            <div className="panel" style={{ position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div style={{ position: 'absolute', top: 0, left: 0, width: 4, height: '100%', background: result.risk === 'clean' ? 'var(--green)' : result.risk === 'suspicious' ? 'var(--amber)' : result.risk === 'malicious' ? 'var(--red)' : 'var(--text-3)' }} />
              <div>
                <div className="row-between" style={{ marginBottom: 24 }}>
                  <span className="section-label">ANALYSIS VERDICT</span>
                  <div className="row" style={{ color: result.risk === 'clean' ? 'var(--green)' : result.risk === 'suspicious' ? 'var(--amber)' : result.risk === 'malicious' ? 'var(--red)' : 'var(--text-3)' }}>
                    {result.risk === 'clean' ? <ShieldCheck size={18} /> : result.risk === 'inconclusive' ? <Info size={18} /> : <ShieldAlert size={18} />}
                    <span className="mono" style={{ fontSize: 14, fontWeight: 700 }}>{result.risk.toUpperCase()}</span>
                  </div>
                </div>
                
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 4 }}>
                  <span className="mono" style={{ fontSize: 48, fontWeight: 700, lineHeight: 1 }}>{result.risk_score}</span>
                  <span className="mono" style={{ fontSize: 18, color: 'var(--text-3)' }}>/100</span>
                </div>
                <div className="section-label" style={{ marginBottom: 24 }}>RISK SCORE</div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
                <div className="row-between">
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>CONFIDENCE</span>
                  <span className="mono" style={{ fontSize: 12, color: 'var(--text)', fontWeight: 600 }}>{result.confidence}%</span>
                </div>
                <div className="row-between">
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>EMAIL TYPE</span>
                  <span className="mono" style={{ fontSize: 12, color: 'var(--text)', fontWeight: 600 }}>{result.email_type}</span>
                </div>
              </div>
            </div>

            {/* AI Summary */}
            <div className="panel" style={{ display: 'flex', flexDirection: 'column' }}>
              <div className="row-between" style={{ marginBottom: 16 }}>
                <div className="row">
                  <Activity size={14} color="var(--text-3)" />
                  <span className="section-label">AI ANALYST SUMMARY</span>
                </div>
              </div>
              <div style={{ flex: 1, color: 'var(--text-2)', fontSize: 14, lineHeight: 1.6 }}>
                {result.ai_summary || 'No AI summary available.'}
              </div>
              <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
                <div className="section-label" style={{ marginBottom: 8 }}>SUBJECT</div>
                <div className="mono" style={{ fontSize: 13, color: 'var(--text)' }}>{result.headers.subject || '—'}</div>
              </div>
            </div>
          </div>

          <div className="grid-2">
            <RiskBreakdown signals={result.signal_breakdown} />
            <EvidenceFindings signals={result.signal_breakdown} />
          </div>

          <div className="grid-3">
            <AuthBadge label="SPF VERIFICATION" auth={result.authentication.spf} icon={Server} />
            <AuthBadge label="DKIM VERIFICATION" auth={result.authentication.dkim} icon={FileKey} />
            <AuthBadge label="DMARC VERIFICATION" auth={result.authentication.dmarc} icon={Shield} />
          </div>

          {/* Header Analysis & Sender */}
          <div className="grid-2">
            <div className="panel">
              <div className="row" style={{ marginBottom: 16 }}>
                <Search size={14} color="var(--text-3)" />
                <span className="section-label">HEADER ANALYSIS</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                <div className="row"><span style={{ color: 'var(--text-3)', width: 90 }}>From:</span> <span style={{ color: 'var(--text)' }}>{result.headers.from.display_name} &lt;{result.headers.from.email}&gt;</span></div>
                {result.headers.reply_to && <div className="row"><span style={{ color: 'var(--text-3)', width: 90 }}>Reply-To:</span> <span style={{ color: 'var(--text)' }}>{result.headers.reply_to.email}</span></div>}
                {result.headers.return_path && <div className="row"><span style={{ color: 'var(--text-3)', width: 90 }}>Return-Path:</span> <span style={{ color: 'var(--text)' }}>{result.headers.return_path.email}</span></div>}
              </div>
              {result.headers.spoofing_flags.length > 0 && (
                <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {result.headers.spoofing_flags.map((flag, i) => (
                    <div key={i} style={{ background: 'var(--amber-dim)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: 'var(--r-md)', padding: '10px 14px', color: 'var(--amber)', fontSize: 12, display: 'flex', gap: 8 }}>
                      <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 2 }} />
                      <span>{flag}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="panel" style={{ border: result.sender_identity.suspicious ? '1px solid var(--red-border)' : undefined }}>
              <div className="row-between" style={{ marginBottom: 16 }}>
                <div className="row">
                  <Fingerprint size={14} color="var(--text-3)" />
                  <span className="section-label">SENDER IDENTITY</span>
                </div>
                <span className="mono" style={{ fontSize: 11, color: result.sender_identity.suspicious ? 'var(--red)' : 'var(--green)', fontWeight: 600 }}>
                  RISK: +{result.sender_identity.risk_contribution}
                </span>
              </div>
              {result.sender_identity.findings.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {result.sender_identity.findings.map((f, i) => (
                    <div key={i} style={{ background: 'var(--red-dim)', border: '1px solid var(--red-border)', borderRadius: 'var(--r-md)', padding: '12px 14px' }}>
                      <div className="row-between" style={{ marginBottom: 4 }}>
                        <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: 'var(--red)' }}>{f.code.replaceAll('_', ' ').toUpperCase()}</span>
                        <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: 'var(--red)' }}>+{f.risk_contribution}</span>
                      </div>
                      <div style={{ fontSize: 12.5, color: 'var(--text-2)' }}>{f.detail}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--green)', fontSize: 13 }}>
                  <CheckCircle2 size={16} />
                  No sender-identity anomalies detected.
                </div>
              )}
            </div>
          </div>

          {/* URLs */}
          {result.urls.length > 0 && (
            <div className="panel">
              <div className="row-between" style={{ marginBottom: 16 }}>
                <div className="row">
                  <LinkIcon size={14} color="var(--text-3)" />
                  <span className="section-label">URL ANALYSIS ({result.urls.length})</span>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {result.urls.map((u, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--surface-2)', borderRadius: 'var(--r-md)', gap: 12 }}>
                    <span className="mono" style={{ fontSize: 12, color: 'var(--text-2)', wordBreak: 'break-all' }}>{u.defanged}</span>
                    <div className="row" style={{ flexShrink: 0 }}>
                      {u.is_shortener && <Tag color="var(--amber)">SHORTENER</Tag>}
                      {u.suspicious_tld && <Tag color="var(--amber)">SUS TLD</Tag>}
                      {(u.vt_malicious || 0) > 0 && <Tag color="var(--red)">{u.vt_malicious}/{u.vt_total} VT</Tag>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attachments */}
          {result.attachments.length > 0 && (
            <div className="panel">
              <div className="row-between" style={{ marginBottom: 16 }}>
                <div className="row">
                  <FileWarning size={14} color="var(--text-3)" />
                  <span className="section-label">ATTACHMENTS ({result.attachments.length})</span>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {result.attachments.map((a, i) => (
                  <div key={i} style={{ padding: '12px 16px', background: 'var(--surface-2)', borderRadius: 'var(--r-md)', border: a.executable || a.suspicious_double_extension ? '1px solid var(--red-border)' : '1px solid transparent' }}>
                    <div className="row-between" style={{ marginBottom: 8 }}>
                      <span className="mono" style={{ fontSize: 13, color: 'var(--text)' }}>{a.filename}</span>
                      {a.dangerous_extension && <Tag color="var(--red)">DANGEROUS EXT</Tag>}
                    </div>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}>
                      TYPE: {a.mime_type} · EXT: {a.extension || 'none'} · SIZE: {a.size_bytes.toLocaleString()} bytes
                    </div>
                    <div className="mono" style={{ fontSize: 10, color: 'var(--text-3)', wordBreak: 'break-all', marginBottom: 10 }}>
                      SHA256: {a.sha256}
                    </div>
                    <div className="row" style={{ flexWrap: 'wrap' }}>
                      {a.executable && <Tag color="var(--red)">EXECUTABLE</Tag>}
                      {a.suspicious_double_extension && <Tag color="var(--red)">DOUBLE EXT</Tag>}
                      {a.macro_enabled && <Tag color="var(--amber)">MACRO-ENABLED</Tag>}
                      {a.archive && <Tag color="var(--amber)">ARCHIVE</Tag>}
                      {a.nested_archive && <Tag color="var(--red)">NESTED ARCHIVE</Tag>}
                      {(a.vt_malicious || 0) > 0 && <Tag color="var(--red)">VT: {a.vt_malicious} malicious</Tag>}
                      {a.mb_found && <Tag color="var(--red)">MalwareBazaar: {a.mb_family}</Tag>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Footer actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
            <button
              onClick={copyReport}
              style={{
                display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px',
                borderRadius: 'var(--r-md)', border: '1px solid var(--border)',
                background: copied ? 'var(--green-dim)' : 'var(--surface)',
                color: copied ? 'var(--green)' : 'var(--text)',
                fontFamily: 'var(--font-sans)', fontSize: 13, fontWeight: 500,
                cursor: 'pointer'
              }}
            >
              {copied ? <Check size={16} /> : <Copy size={16} />}
              {copied ? 'Report Copied' : 'Copy Incident Report'}
            </button>
          </div>

        </div>
      )}
    </main>
  )
}
