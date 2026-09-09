import re

with open('/mnt/Matrix/CyberSecurity-Projects/phishing-analyzer/frontend/app/page.tsx', 'r') as f:
    content = f.read()

# Add signal_breakdown to AnalysisResult
content = content.replace(
    '  mitre_attack: { id: string; name: string }[]\n}',
    '  mitre_attack: { id: string; name: string }[]\n  signal_breakdown: { signal: string; weight: number; applied: boolean }[]\n}'
)

# Add helper functions and RiskBreakdown component after type definitions
helpers = """
const getCategory = (signal: string) => {
  if (signal.startsWith('spf_') || signal.startsWith('dkim_') || signal.startsWith('dmarc_') || signal.startsWith('corroborated_')) return 'Authentication'
  if (signal.startsWith('from_') || signal.startsWith('display_name_') || signal.startsWith('sender_')) return 'Sender Analysis'
  if (signal.startsWith('suspicious_url') || signal.startsWith('confirmed_malicious_url') || signal.startsWith('url_domain_mismatch')) return 'URL Analysis'
  if (signal.startsWith('suspicious_attachment') || signal.startsWith('known_malicious_attachment')) return 'Attachment Analysis'
  if (signal.startsWith('content_') || signal.startsWith('credential_harvesting_') || signal.startsWith('normal_')) return 'Content'
  if (signal.startsWith('mime_')) return 'MIME'
  return 'Other'
}

const getSeverity = (weight: number) => {
  if (weight >= 40) return { label: 'CRITICAL', icon: '🔴', color: 'var(--danger)' }
  if (weight >= 15) return { label: 'HIGH', icon: '🟠', color: '#FF9F43' }
  if (weight >= 8) return { label: 'MEDIUM', icon: '🟡', color: '#FDCB6E' }
  if (weight > 0) return { label: 'LOW', icon: '🔵', color: '#74B9FF' }
  return { label: 'INFORMATIONAL', icon: '⚪', color: 'var(--text-muted)' }
}

function RiskBreakdown({ signals }: { signals: { signal: string; weight: number; applied: boolean }[] }) {
  const categories: Record<string, { total: number; items: typeof signals }> = {}
  
  signals.forEach(s => {
    const cat = getCategory(s.signal)
    if (!categories[cat]) categories[cat] = { total: 0, items: [] }
    categories[cat].total += s.weight
    categories[cat].items.push(s)
  })

  const [expanded, setExpanded] = useState<string | null>(null)

  const totalScore = Object.values(categories).reduce((acc, cat) => acc + cat.total, 0)

  return (
    <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: 24 }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: 4 }}>Why?</div>
      <div style={{ fontSize: 14, fontWeight: 'bold', marginBottom: 16, letterSpacing: '0.05em' }}>RISK BREAKDOWN</div>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {Object.entries(categories).map(([cat, data]) => (
          <div key={cat} style={{ background: 'var(--surface-2)', borderRadius: 8, overflow: 'hidden', border: '1px solid var(--muted-border)' }}>
            <div 
              onClick={() => setExpanded(expanded === cat ? null : cat)}
              style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 13 }}
            >
              <span>{cat}</span>
              <span style={{ color: data.total > 0 ? 'var(--accent-coral)' : data.total < 0 ? 'var(--accent-emerald)' : 'var(--text-muted)' }}>
                {data.total > 0 ? '+' : ''}{data.total}
              </span>
            </div>
            {expanded === cat && (
              <div style={{ padding: '0 16px 12px 16px', display: 'flex', flexDirection: 'column', gap: 8, borderTop: '1px solid var(--muted-border)' }}>
                <div style={{ height: 4 }} />
                {data.items.map(s => {
                  const sev = getSeverity(s.weight)
                  return (
                    <div key={s.signal} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-dim)', alignItems: 'center' }}>
                      <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <span title={sev.label}>{sev.icon}</span>
                        <span>{s.signal.replaceAll('_', ' ')}</span>
                      </span>
                      <span>{s.weight > 0 ? '+' : ''}{s.weight}</span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        ))}
      </div>
      
      <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px dashed var(--muted-border)', display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 'bold' }}>
        <span>Total</span>
        <span>{totalScore}</span>
      </div>
    </div>
  )
}
"""

content = content.replace('function AuthBadge', helpers + '\nfunction AuthBadge')

# Modify Top Card
top_card = """          {/* Top Card & AI Summary & Risk Breakdown */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(250px, 1fr) minmax(300px, 1.5fr)', gap: 16 }}>
              {/* Verdict Card */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: 24, display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
                <div style={{ position: 'absolute', top: 0, left: 0, width: 4, height: '100%', background: result.risk === 'clean' ? 'var(--accent-emerald)' : result.risk === 'suspicious' ? 'var(--accent-coral)' : 'var(--danger)' }} />
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 18, fontWeight: 'bold', color: result.risk === 'clean' ? 'var(--accent-emerald)' : result.risk === 'suspicious' ? 'var(--accent-coral)' : 'var(--danger)', marginBottom: 24, letterSpacing: '0.05em' }}>
                  {result.risk.toUpperCase()}
                </div>
                
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 36, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{result.risk_score}</span>
                  <span style={{ fontSize: 18, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>/ 100</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 24, fontFamily: 'var(--font-mono)' }}>
                  Risk Score
                </div>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text)' }}>
                  <div><span style={{ color: 'var(--text-muted)' }}>Confidence:</span> {result.confidence}%</div>
                  <div><span style={{ color: 'var(--text-muted)' }}>Email Type:</span> {result.email_type}</div>
                </div>
              </div>

              {/* AI Summary */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--muted-border)', borderRadius: 12, padding: '24px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.12em', color: 'var(--accent-emerald)', background: 'var(--accent-emerald-dim)', padding: '2px 8px', borderRadius: 4 }}>AI SUMMARY</span>
                <p style={{ color: 'var(--text)', fontSize: 14, lineHeight: 1.7, fontStyle: 'italic', marginTop: 12 }}>{result.ai_summary}</p>
                <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--muted-border)' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: 3 }}>SUBJECT</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12.5, color: 'var(--text)' }}>{result.headers.subject}</div>
                </div>
              </div>
            </div>

            {/* Risk Breakdown */}
            <RiskBreakdown signals={result.signal_breakdown} />
          </div>"""

# Find the old Risk + AI Summary section and replace it
import re
content = re.sub(
    r'\{\/\* Risk \+ AI Summary \*\/\}.*?\{\/\* Header Analysis \*\/\}',
    top_card + '\n\n          {/* Header Analysis */}',
    content,
    flags=re.DOTALL
)

with open('/mnt/Matrix/CyberSecurity-Projects/phishing-analyzer/frontend/app/page.tsx', 'w') as f:
    f.write(content)

print("Rewrite complete.")
