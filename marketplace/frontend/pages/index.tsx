import Head from 'next/head';
import Link from 'next/link';
import Layout from '../components/Layout';

const categories = [
	{ id: 'software', label: 'Software', icon: '💻' },
	{ id: 'ebooks', label: 'E-books', icon: '📚' },
	{ id: 'services', label: 'Services', icon: '🛠️' },
	{ id: 'physical', label: 'Physical Goods', icon: '📦' },
];

const products = [
	{
		id: '1',
		title: 'Encrypted Messaging App',
		price: '0.25', // BLK
		category: 'software',
		featured: true,
	},
	{
		id: '2',
		title: 'OpSec Mastery E-book',
		price: '0.05', // BLK
		category: 'ebooks',
		featured: true,
	},
	{
		id: '3',
		title: 'Anonymous Hosting',
		price: '0.10', // BLK
		category: 'services',
		featured: false,
	},
	{
		id: '4',
		title: 'Raspberry Pi Privacy Kit',
		price: '0.30', // BLK
		category: 'physical',
		featured: false,
	},
];

function Sidebar() {
	return (
		<div>
			<h2 className="text-lg font-bold mb-4 text-green-500">Categories</h2>
			<ul className="space-y-2 mb-8">
				{categories.map(cat => (
					<li key={cat.id}>
						<Link
							href={`/category/${cat.id}`}
							className="flex items-center px-2 py-1 rounded hover:bg-[#23232a] transition"
						>
							<span className="mr-2 text-xl">{cat.icon}</span>
							{cat.label}
						</Link>
					</li>
				))}
			</ul>
			<h2 className="text-lg font-bold mb-4 text-green-500">Quick Links</h2>
			<ul className="space-y-2">
				<li>
					<Link href="/sell" className="hover:underline">
						Sell an Item
					</Link>
				</li>
				<li>
					<Link href="/account" className="hover:underline">
						My Account
					</Link>
				</li>
				<li>
					<Link href="/orders" className="hover:underline">
						My Orders
					</Link>
				</li>
			</ul>
		</div>
	);
}

export default function Home() {
	return (
		<Layout sidebar={<Sidebar />}>
			<Head>
				<title>BlackSilk Marketplace</title>
			</Head>
			<div className="mb-10">
				<h1 className="text-3xl font-extrabold text-green-500 mb-2">
					BlackSilk Marketplace
				</h1>
				<p className="text-gray-400 mb-6">
					A simple, private, decentralized market. Inspired by Silk Road.
				</p>
			</div>
			<section className="mb-10">
				<h2 className="text-xl font-bold mb-4 text-green-400">
					Featured Products
				</h2>
				<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
					{products
						.filter(p => p.featured)
						.map(product => (
							<Link
								key={product.id}
								href={`/product/${product.id}`}
								className="block bg-[#19191c] rounded border border-[#23232a] p-4 hover:bg-[#23232a] transition"
							>
								<div className="flex items-center mb-2">
									<span className="text-2xl mr-3">
										{
											categories.find(c => c.id === product.category)
												?.icon
										}
									</span>
									<span className="text-gray-400 text-sm">
										{
											categories.find(c => c.id === product.category)
												?.label
										}
									</span>
								</div>
								<div className="font-bold text-lg text-white mb-1">
									{product.title}
								</div>
								<div className="text-green-400 font-semibold">
									{product.price} BLK
								</div>
							</Link>
						))}
				</div>
			</section>
			<section>
				<h2 className="text-xl font-bold mb-4 text-green-400">All Products</h2>
				<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
					{products.map(product => (
						<Link
							key={product.id}
							href={`/product/${product.id}`}
							className="block bg-[#19191c] rounded border border-[#23232a] p-4 hover:bg-[#23232a] transition"
						>
							<div className="flex items-center mb-2">
								<span className="text-2xl mr-3">
									{
										categories.find(c => c.id === product.category)
											?.icon
									}
								</span>
								<span className="text-gray-400 text-sm">
									{
										categories.find(c => c.id === product.category)
											?.label
									}
								</span>
							</div>
							<div className="font-bold text-lg text-white mb-1">
								{product.title}
							</div>
							<div className="text-green-400 font-semibold">
								{product.price} BLK
							</div>
						</Link>
					))}
				</div>
			</section>
			<div className="mt-12 text-center text-gray-500 text-sm">
				Privacy first. Decentralized. Inspired by Silk Road.
			</div>
		</Layout>
	);
}