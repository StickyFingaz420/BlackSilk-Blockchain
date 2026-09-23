import './globals.css'
import { Inter } from 'next/font/google'
import { Providers } from './providers'
import { Header } from '@/components/layout/Header'
import { Footer } from '@/components/layout/Footer'

const inter = Inter({ subsets: ['latin'] })

export const metadata = {
  title: 'BlackSilk Block Explorer',
  description: 'Explore the BlackSilk blockchain - view blocks, transactions, addresses, and network statistics',
  keywords: ['blockchain', 'explorer', 'blacksilk', 'cryptocurrency', 'privacy'],
  authors: [{ name: 'BlackSilk Development Team' }],
  viewport: 'width=device-width, initial-scale=1',
  themeColor: '#8B5CF6',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <Providers>
          <div className="min-h-screen flex flex-col">
            <Header />
            <main className="flex-1">
              {children}
            </main>
            <Footer />
          </div>
        </Providers>
      </body>
    </html>
  )
}
