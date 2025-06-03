import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Toaster } from 'react-hot-toast';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'BlackSilk Testnet Faucet',
  description: 'Get free BlackSilk testnet tokens for development and testing',
  keywords: 'BlackSilk, testnet, faucet, cryptocurrency, blockchain, tBLK tokens',
  authors: [{ name: 'BlackSilk Team' }],
  viewport: 'width=device-width, initial-scale=1',
  robots: 'index, follow',
  openGraph: {
    title: 'BlackSilk Testnet Faucet',
    description: 'Get free BlackSilk testnet tokens for development and testing',
    type: 'website',
    siteName: 'BlackSilk Testnet Faucet',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'BlackSilk Testnet Faucet',
    description: 'Get free BlackSilk testnet tokens for development and testing',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-violet-800">
          {children}
          <Toaster
            position="top-right"
            toastOptions={{
              duration: 4000,
              style: {
                background: '#363636',
                color: '#fff',
              },
              success: {
                duration: 3000,
                style: {
                  background: '#059669',
                },
              },
              error: {
                duration: 5000,
                style: {
                  background: '#DC2626',
                },
              },
            }}
          />
        </div>
      </body>
    </html>
  );
}
