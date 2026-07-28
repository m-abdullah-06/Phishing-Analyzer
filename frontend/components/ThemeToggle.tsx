"use client"

import { useEffect, useState } from 'react'

export default function ThemeToggle() {
  const [light, setLight] = useState(false)

  useEffect(() => {
    try {
      const saved = localStorage.getItem('pha:theme')
      const prefers = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
      if (saved) {
        setLight(saved === 'light')
        document.documentElement.classList.toggle('theme-light', saved === 'light')
      } else {
        setLight(prefers)
        document.documentElement.classList.toggle('theme-light', prefers)
      }
    } catch (e) {}
  }, [])

  const toggle = () => {
    const next = !light
    setLight(next)
    try {
      localStorage.setItem('pha:theme', next ? 'light' : 'dark')
      document.documentElement.classList.toggle('theme-light', next)
    } catch (e) {}
  }

  return (
    <button aria-pressed={light} onClick={toggle} className="btn-pill" style={{ border: '1px solid var(--muted-border)', background: 'var(--surface)', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
      {light ? '☀️ Light' : '🌙 Dark'}
    </button>
  )
}
