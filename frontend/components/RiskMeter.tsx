'use client'

import { useEffect, useState } from 'react'

interface RiskMeterProps {
  score: number
  risk: 'clean' | 'suspicious' | 'malicious'
}

const RISK_COLORS = { clean: 'var(--accent-emerald)', suspicious: 'var(--accent-coral)', malicious: 'var(--danger)' }

export default function RiskMeter({ score, risk }: RiskMeterProps) {
  const [animatedScore, setAnimatedScore] = useState(0)

  useEffect(() => {
    const timer = setTimeout(() => {
      let current = 0
      const interval = setInterval(() => {
        current += 2
        if (current >= score) {
          setAnimatedScore(score)
          clearInterval(interval)
        } else {
          setAnimatedScore(current)
        }
      }, 16)
      return () => clearInterval(interval)
    }, 200)
    return () => clearTimeout(timer)
  }, [score])

  const radius = 52
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference
  const color = RISK_COLORS[risk]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
      <div style={{ position: 'relative', width: 140, height: 140 }}>
        <svg width="140" height="140" viewBox="0 0 140 140" style={{ transform: 'rotate(-90deg)' }}>
          <defs>
            <linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={color} stopOpacity="0.92" />
              <stop offset="100%" stopColor={color} stopOpacity="0.6" />
            </linearGradient>
          </defs>
          <circle cx="70" cy="70" r={radius} fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="12" />
          <circle
            cx="70" cy="70" r={radius} fill="none" stroke="url(#g1)" strokeWidth="12" strokeLinecap="round"
            strokeDasharray={circumference} strokeDashoffset={strokeDashoffset}
            style={{ transition: 'stroke-dashoffset 420ms cubic-bezier(.2,.9,.2,1)', filter: `drop-shadow(0 6px 18px ${color}33)` }}
          />
        </svg>
        <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '30px', fontWeight: 800, color, lineHeight: 1 }}>{animatedScore}</span>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginTop: 6 }}>RISK SCORE</span>
        </div>
      </div>
      <div style={{
        padding: '6px 18px', borderRadius: '8px',
        background: risk === 'clean' ? 'var(--accent-emerald-dim)' : risk === 'suspicious' ? 'var(--accent-coral-dim)' : 'rgba(255,90,90,0.08)',
        border: `1px solid ${color}33`, fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 700, letterSpacing: '0.12em', color,
      }}>
        {risk.toUpperCase()}
      </div>
    </div>
  )
}
