import Head from 'next/head';
import Link from 'next/link';
import Layout from '../components/Layout';

const categories = [
	{ id: 'software', label: 'Software' },
	{ id: 'ebooks', label: 'E-books' },
	{ id: 'services', label: 'Services' },
	{ id: 'physical', label: 'Physical Goods' },
];

const products = [
	{ id: '1', title: 'Encrypted Messaging App', price: '0.25', category: 'software' },
	{ id: '2', title: 'OpSec Mastery E-book', price: '0.05', category: 'ebooks' },
	{ id: '3', title: 'Anonymous Hosting', price: '0.10', category: 'services' },
	{ id: '4', title: 'Raspberry Pi Privacy Kit', price: '0.30', category: 'physical' },
];

function Sidebar() {
	return (
		<div className="bg-[#222] border-r border-[#333] min-h-screen p-0 w-56">
			<div className="p-4 border-b border-[#333] text-green-400 font-bold text-lg tracking-widest text-center">
				Categories
			</div>
			<ul className="py-2 px-2 text-sm text-gray-200">
				{categories.map(cat => (
					<li key={cat.id} className="mb-2">
						<Link
							href={`/category/${cat.id}`}
							className="block px-2 py-1 rounded hover:bg-[#333] hover:text-green-300 transition"
						>
							{cat.label}
						</Link>
					</li>
				))}
			</ul>
		</div>
	);
}

export default function Home() {
	return (
		<Layout sidebar={<Sidebar />}>
			<Head>
				<title>BlackSilk Market</title>
			</Head>
			<div className="max-w-5xl mx-auto mt-8">
				<div className="mb-8 border-b border-[#333] pb-4 flex items-center gap-4">
					<span className="text-green-400 font-black text-3xl tracking-tight font-serif">
						BlackSilk
					</span>
					<span className="text-gray-300 text-base font-mono">
						Welcome to the BlackSilk Market &mdash; All prices in BLK
					</span>
				</div>
				<div className="overflow-x-auto rounded shadow border border-[#333] bg-[#181818]">
					<table className="min-w-full text-left font-mono text-sm">
						<thead>
							<tr className="bg-[#232323] text-green-400">
								<th className="py-2 px-4 font-bold">Product</th>
								<th className="py-2 px-4 font-bold">Category</th>
								<th className="py-2 px-4 font-bold">Price (BLK)</th>
							</tr>
						</thead>
						<tbody>
							{products.map(product => (
								<tr
									key={product.id}
									className="border-t border-[#333] hover:bg-[#222] transition"
								>
									<td className="py-2 px-4">
										<Link
											href={`/product/${product.id}`}
											className="text-green-300 hover:underline"
										>
											{product.title}
										</Link>
									</td>
									<td className="py-2 px-4 text-gray-300">
										{
											categories.find(c => c.id === product.category)
												?.label || product.category
										}
									</td>
									<td className="py-2 px-4 text-white">{product.price}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
				<div className="mt-8 text-center text-gray-500 text-xs font-mono">
					BlackSilk is a privacy-first market. All transactions in BLK. Use Tor for
					maximum anonymity.
				</div>
			</div>
		</Layout>
	);
}