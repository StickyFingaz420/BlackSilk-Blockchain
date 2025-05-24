import React, { useEffect, useState } from 'react';
import Link from 'next/link';

export default function Layout({ children, sidebar }: { children: React.ReactNode, sidebar?: React.ReactNode }) {
  const [address, setAddress] = useState<string | null>(null);
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setAddress(sessionStorage.getItem('blacksilk_priv') ? 'Wallet Connected' : null);
    }
  }, []);
  return (
    <div className="min-h-screen flex flex-col bg-[#181818] text-white font-mono">
      <header className="bg-[#232323] text-green-400 py-3 px-6 flex items-center justify-between border-b border-[#333] shadow-sm">
        <div className="flex items-center gap-4">
          <Link href="/">
            <span className="font-black text-2xl tracking-tight font-serif">BlackSilk</span>
          </Link>
          <span className="text-xs text-gray-400 font-mono">Decentralized Silk Road Market</span>
        </div>
        <nav className="space-x-4 flex items-center text-sm">
          <Link href="/sell" className="hover:text-white transition">Sell</Link>
          <Link href="/account" className="hover:text-white transition">Account</Link>
          <Link href="/orders" className="hover:text-white transition">Orders</Link>
          {address && <span className="ml-4 px-2 py-1 bg-green-900 text-green-200 rounded text-xs">{address}</span>}
        </nav>
      </header>
      <div className="flex flex-1 w-full max-w-7xl mx-auto">
        {sidebar && (
          <aside className="hidden md:block w-56 bg-[#222] border-r border-[#333] p-0">{sidebar}</aside>
        )}
        <main className="flex-1 px-2 md:px-8 py-8 bg-[#181818]">{children}</main>
      </div>
      <footer className="bg-[#232323] text-center py-4 text-gray-600 text-xs border-t border-[#333]">
        &copy; {new Date().getFullYear()} BlackSilk Marketplace
      </footer>
    </div>
  );
}
