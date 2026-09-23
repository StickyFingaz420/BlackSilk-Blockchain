import Link from 'next/link'
import { Github, Twitter, Book, MessageCircle } from 'lucide-react'

export function Footer() {
  const currentYear = new Date().getFullYear()

  const links = {
    explore: [
      { name: 'Latest Blocks', href: '/blocks' },
      { name: 'Recent Transactions', href: '/transactions' },
      { name: 'Network Stats', href: '/charts' },
      { name: 'Mempool', href: '/mempool' },
    ],
    tools: [
      { name: 'Testnet Faucet', href: process.env.NEXT_PUBLIC_FAUCET_URL || '#' },
      { name: 'API Documentation', href: '/api' },
      { name: 'Node Setup', href: '/docs/node-setup' },
      { name: 'Mining Guide', href: '/docs/mining' },
    ],
    community: [
      { name: 'GitHub', href: process.env.NEXT_PUBLIC_GITHUB_URL || '#', icon: Github },
      { name: 'Documentation', href: process.env.NEXT_PUBLIC_DOCS_URL || '#', icon: Book },
      { name: 'Discord', href: '#', icon: MessageCircle },
      { name: 'Twitter', href: '#', icon: Twitter },
    ],
  }

  return (
    <footer className="bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-800">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="space-y-4">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center">
                <span className="text-white font-bold text-sm">BS</span>
              </div>
              <div>
                <div className="font-bold text-gray-900 dark:text-white">
                  BlackSilk Explorer
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Privacy-first blockchain
                </div>
              </div>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400 max-w-xs">
              Explore the BlackSilk blockchain with our comprehensive block explorer. 
              View blocks, transactions, addresses, and network statistics.
            </p>
          </div>

          {/* Explore */}
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Explore</h3>
            <ul className="space-y-2">
              {links.explore.map((link) => (
                <li key={link.name}>
                  <Link
                    href={link.href}
                    className="text-sm text-gray-600 dark:text-gray-400 hover:text-primary-600 dark:hover:text-primary-400 transition-colors duration-200"
                  >
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Tools */}
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Tools</h3>
            <ul className="space-y-2">
              {links.tools.map((link) => (
                <li key={link.name}>
                  <Link
                    href={link.href}
                    className="text-sm text-gray-600 dark:text-gray-400 hover:text-primary-600 dark:hover:text-primary-400 transition-colors duration-200"
                  >
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Community */}
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Community</h3>
            <ul className="space-y-2">
              {links.community.map((link) => (
                <li key={link.name}>
                  <a
                    href={link.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400 hover:text-primary-600 dark:hover:text-primary-400 transition-colors duration-200"
                  >
                    <link.icon className="w-4 h-4" />
                    <span>{link.name}</span>
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="mt-8 pt-8 border-t border-gray-200 dark:border-gray-800">
          <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
            <div className="text-sm text-gray-600 dark:text-gray-400">
              © {currentYear} BlackSilk Development Team. Open source under MIT License.
            </div>
            <div className="flex items-center space-x-6">
              <Link
                href="/privacy"
                className="text-sm text-gray-600 dark:text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"
              >
                Privacy Policy
              </Link>
              <Link
                href="/terms"
                className="text-sm text-gray-600 dark:text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"
              >
                Terms of Service
              </Link>
              <div className="flex items-center space-x-1 text-sm text-gray-500 dark:text-gray-400">
                <span>Network:</span>
                <span className="font-medium text-primary-600 dark:text-primary-400">
                  {process.env.NEXT_PUBLIC_NETWORK_NAME || 'Testnet'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </footer>
  )
}
