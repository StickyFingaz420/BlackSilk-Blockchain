import React, { useEffect, useState } from 'react';
import Link from 'next/link';

const navLinks = [
  { href: '/sell', label: 'Sell' },
  { href: '/account', label: 'Account' },
  { href: '/orders', label: 'Orders' },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const [address, setAddress] = useState<string | null>(null);
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setAddress(sessionStorage.getItem('blacksilk_priv') ? 'Wallet Connected' : null);
    }
  }, []);
  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-[#18181b] via-[#23232a] to-[#101014] text-white font-sans">
      <header className="bg-[#18181b] text-white py-4 px-8 flex items-center justify-between border-b border-[#23232a] shadow">
        <Link href="/">
          <span className="font-bold text-2xl tracking-tight hover:text-blue-400 transition">BlackSilk</span>
        </Link>
        <nav className="space-x-6 flex items-center">
          {navLinks.map(link => (
            <Link key={link.href} href={link.href} className="hover:text-blue-400 text-lg font-medium transition">
              {link.label}
            </Link>
          ))}
          {address && <span className="ml-4 px-2 py-1 bg-green-700 rounded text-xs">{address}</span>}
        </nav>
      </header>
      <main className="flex-1">{children}</main>
      <footer className="bg-[#23232a] text-center py-4 text-gray-500 text-sm border-t border-[#23232a]">
        &copy; {new Date().getFullYear()} BlackSilk Marketplace
      </footer>
    </div>
  );
}
