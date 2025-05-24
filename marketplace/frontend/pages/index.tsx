import Head from 'next/head';
import Link from 'next/link';

const tabs = [
  { id: 'software', label: 'Software', icon: '💻' },
  { id: 'ebooks', label: 'E-books', icon: '📚' },
  { id: 'services', label: 'Services', icon: '🛠️' },
  { id: 'physical', label: 'Physical Goods', icon: '📦' },
];

export default function Home() {
  return (
    <>
      <Head>
        <title>BlackSilk Marketplace</title>
      </Head>
      <main className="min-h-screen bg-gradient-to-br from-[#18181b] via-[#23232a] to-[#101014] text-white font-sans">
        <div className="max-w-5xl mx-auto py-12 px-4">
          <div className="flex flex-col items-center mb-10">
            <h1 className="text-5xl font-extrabold mb-2 tracking-tight text-white drop-shadow-lg text-center">
              BlackSilk Marketplace
            </h1>
            <span className="text-gray-400 text-lg mt-2 mb-6 text-center">
              The next-generation private market. Inspired by Silk Road.
            </span>
          </div>
          <nav className="flex justify-center mb-12">
            <div className="flex bg-[#23232a] rounded-lg shadow overflow-hidden border border-[#333]">
              {tabs.map(tab => (
                <Link
                  key={tab.id}
                  href={`/category/${tab.id}`}
                  className="flex items-center px-8 py-4 text-lg font-semibold hover:bg-[#18181b] transition border-r border-[#333] last:border-r-0 focus:outline-none focus:bg-[#23232a]"
                >
                  <span className="mr-2 text-2xl">{tab.icon}</span>
                  {tab.label}
                </Link>
              ))}
            </div>
          </nav>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 mt-8">
            {tabs.map(tab => (
              <Link
                key={tab.id}
                href={`/category/${tab.id}`}
                className="block bg-[#23232a] text-white rounded-xl shadow-lg p-8 hover:bg-[#18181b] transition border border-[#333] group"
              >
                <div className="flex flex-col items-center">
                  <span className="text-5xl mb-4 group-hover:scale-110 transition-transform">{tab.icon}</span>
                  <span className="text-xl font-bold mb-2">{tab.label}</span>
                  <span className="text-gray-400 text-sm text-center">Browse all {tab.label.toLowerCase()} listings</span>
                </div>
              </Link>
            ))}
          </div>
          <div className="mt-16 text-center text-gray-400 text-lg">
            <span className="font-semibold">Privacy-first. Decentralized. Inspired by Silk Road.</span>
            <span className="block text-sm mt-2">All transactions are private, non-custodial, and censorship-resistant.</span>
          </div>
        </div>
      </main>
    </>
  );
}