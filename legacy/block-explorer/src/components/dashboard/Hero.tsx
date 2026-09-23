'use client'

import { motion } from 'framer-motion'
import { Shield, Zap, Users, Eye } from 'lucide-react'

export function Hero() {
  const features = [
    {
      icon: Shield,
      title: 'Privacy First',
      description: 'Advanced privacy features including ring signatures and stealth addresses',
    },
    {
      icon: Zap,
      title: 'CPU Mining',
      description: 'RandomX algorithm ensures fair, ASIC-resistant mining for everyone',
    },
    {
      icon: Users,
      title: 'Decentralized',
      description: 'Community-driven governance with transparent decision making',
    },
    {
      icon: Eye,
      title: 'Transparent',
      description: 'Open source blockchain with full transaction visibility',
    },
  ]

  return (
    <section className="relative overflow-hidden">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary-50 via-purple-50 to-indigo-50 dark:from-primary-900/20 dark:via-purple-900/20 dark:to-indigo-900/20" />
      
      {/* Content */}
      <div className="relative">
        <div className="text-center py-16 space-y-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="space-y-4"
          >
            <h1 className="text-4xl md:text-6xl font-bold bg-gradient-to-r from-primary-600 via-purple-600 to-indigo-600 bg-clip-text text-transparent">
              BlackSilk Explorer
            </h1>
            <p className="text-lg md:text-xl text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
              Explore the privacy-first blockchain. View blocks, transactions, and network statistics 
              in real-time with our comprehensive block explorer.
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="flex flex-wrap justify-center gap-4"
          >
            <div className="px-4 py-2 rounded-full bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300 text-sm font-medium">
              🌐 {process.env.NEXT_PUBLIC_NETWORK_NAME || 'Testnet'}
            </div>
            <div className="px-4 py-2 rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 text-sm font-medium">
              ⚡ RandomX Mining
            </div>
            <div className="px-4 py-2 rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 text-sm font-medium">
              🔒 Privacy Features
            </div>
            <div className="px-4 py-2 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-sm font-medium">
              🛒 Marketplace Ready
            </div>
          </motion.div>
        </div>

        {/* Features Grid */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 pb-16"
        >
          {features.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.5 + index * 0.1 }}
              className="card p-6 text-center hover:shadow-lg transition-shadow duration-300"
            >
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-primary-100 dark:bg-primary-900/30 text-primary-600 dark:text-primary-400 mb-4">
                <feature.icon className="w-6 h-6" />
              </div>
              <h3 className="font-semibold text-gray-900 dark:text-white mb-2">
                {feature.title}
              </h3>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                {feature.description}
              </p>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  )
}
