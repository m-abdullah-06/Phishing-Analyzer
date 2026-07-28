import type { Metadata } from 'next'
import { Sora, JetBrains_Mono } from 'next/font/google'
import './globals.css'
import ThemeToggle from '@/components/ThemeToggle'

const sora = Sora({ subsets: ['latin'], variable: '--font-display', weight: ['400','600','700'] })
const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono', weight: ['400','700'] })

export const metadata: Metadata = {
  title: 'Phishing Email Analyzer',
  description: 'Upload a suspicious email — get SPF/DKIM/DMARC verification, spoofing detection, IOC enrichment, and an auto-generated incident report.',
  icons: {
    icon: '/favicon.png',
    apple: '/favicon.png',
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sora.variable} ${jetbrainsMono.variable}`}>
      <body>
        <div style={{ padding: '18px 20px', borderBottom: '1px solid var(--muted-border)', background: 'linear-gradient(180deg, rgba(255,255,255,0.01), transparent)' }}>
          <div style={{ maxWidth: 1100, margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 48, height: 48, borderRadius: 12, background: 'linear-gradient(135deg, var(--accent-emerald), var(--accent-coral))', boxShadow: '0 10px 30px rgba(6,16,12,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <img src="/favicon.png" alt="Phishing Email Analyzer icon" style={{ width: 28, height: 28, objectFit: 'contain' }} />
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 800, letterSpacing: '-0.01em' }}>Phishing Email Analyzer</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Email forensics · SPF/DKIM/DMARC</div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <ThemeToggle />
            </div>
          </div>
        </div>
        <div style={{ maxWidth: 1100, margin: '28px auto' }}>{children}</div>
      </body>
    </html>
  )
}
