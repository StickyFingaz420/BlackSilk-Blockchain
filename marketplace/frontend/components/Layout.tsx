import React, { useEffect, useState } from 'react';
import Link from 'next/link';

const navLinks = [
  { href: '/sell', label: 'Sell' },
  { href: '/account', label: 'Account' },
  { href: '/orders', label: 'Orders' },
];

export default function Layout({ children, sidebar }: { children: React.ReactNode, sidebar?: React.ReactNode }) {
  const [address, setAddress] = useState<string | null>(null);
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setAddress(sessionStorage.getItem('blacksilk_priv') ? 'Wallet Connected' : null);
    }
  }, []);
  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-[#18181b] via-[#23232a] to-[#101014] text-white font-sans">
      <header className="bg-[#101014] text-white py-5 px-8 flex items-center justify-between border-b border-[#23232a] shadow-lg relative z-10">
        <div className="flex items-center space-x-4">
          <Link href="/">
            <span className="font-black text-3xl tracking-tight text-green-400 drop-shadow-glow hover:text-green-300 transition">BlackSilk</span>
          </Link>
          <span className="hidden md:inline text-gray-500 text-sm italic ml-4">Decentralized. Private. Inspired by Silk Road.</span>
        </div>
        <nav className="space-x-6 flex items-center">
          {navLinks.map(link => (
            <Link key={link.href} href={link.href} className="hover:text-green-400 text-lg font-medium transition">
              {link.label}
            </Link>
          ))}
          {address && <span className="ml-4 px-2 py-1 bg-green-700 rounded text-xs shadow">{address}</span>}
        </nav>
      </header>
      <div className="flex flex-1 w-full max-w-7xl mx-auto">
        {sidebar && (
          <aside className="hidden md:block w-64 bg-[#18181b] border-r border-[#23232a] p-6 pr-2 text-gray-200 min-h-[calc(100vh-120px)]">
            {sidebar}
          </aside>
        )}
        <main className="flex-1 px-2 md:px-8 py-8">{children}</main>
      </div>
      <footer className="bg-[#23232a] text-center py-4 text-gray-500 text-sm border-t border-[#23232a]">
        &copy; {new Date().getFullYear()} BlackSilk Marketplace
      </footer>
    </div>
  );
}
