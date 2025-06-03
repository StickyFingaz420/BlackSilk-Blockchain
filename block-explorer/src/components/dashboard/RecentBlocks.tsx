'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { ArrowRight, Clock, Hash } from 'lucide-react'
import api from '@/lib/api'
import { formatTimeAgo, formatNumber, formatHash } from '@/lib/utils'
import type { Block } from '@/types'

interface BlockCardProps {
  block: Block
  index: number
}

function BlockCard({ block, index }: BlockCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.5, delay: index * 0.1 }}
    >
      <Link
        href={`/block/${block.height}`}
        className="block card p-4 hover:shadow-lg transition-all duration-300 hover:scale-105"
      >
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center">
              <Hash className="w-4 h-4 text-primary-600 dark:text-primary-400" />
            </div>
            <div>
              <div className="font-semibold text-gray-900 dark:text-white">
                Block #{formatNumber(block.height)}
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">
                {block.tx_count} transactions
              </div>
            </div>
          </div>
          <ArrowRight className="w-4 h-4 text-gray-400 dark:text-gray-500" />
        </div>

        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-500 dark:text-gray-400">Hash:</span>
            <span className="font-mono text-gray-900 dark:text-white">
              {formatHash(block.hash, 6, 6)}
            </span>
          </div>
          
          <div className="flex justify-between">
            <span className="text-gray-500 dark:text-gray-400">Time:</span>
            <span className="text-gray-900 dark:text-white flex items-center space-x-1">
              <Clock className="w-3 h-3" />
              <span>{formatTimeAgo(block.timestamp)}</span>
            </span>
          </div>
          
          <div className="flex justify-between">
            <span className="text-gray-500 dark:text-gray-400">Difficulty:</span>
            <span className="text-gray-900 dark:text-white">
              {formatNumber(block.difficulty)}
            </span>
          </div>

          {block.reward && (
            <div className="flex justify-between">
              <span className="text-gray-500 dark:text-gray-400">Reward:</span>
              <span className="text-green-600 dark:text-green-400 font-medium">
                {block.reward} BLK
              </span>
            </div>
          )}
        </div>
      </Link>
    </motion.div>
  )
}

export function RecentBlocks() {
  const [blocks, setBlocks] = useState<Block[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchBlocks = async () => {
      try {
        const latestBlocks = await api.getLatestBlocks(5)
        setBlocks(latestBlocks)
        setError(null)
      } catch (err) {
        console.error('Failed to fetch recent blocks:', err)
        setError('Failed to load recent blocks')
      } finally {
        setLoading(false)
      }
    }

    fetchBlocks()
    
    // Update blocks every 30 seconds
    const interval = setInterval(fetchBlocks, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white">
          Recent Blocks
        </h2>
        <Link
          href="/blocks"
          className="text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 text-sm font-medium flex items-center space-x-1 transition-colors duration-200"
        >
          <span>View all</span>
          <ArrowRight className="w-4 h-4" />
        </Link>
      </div>

      {error ? (
        <div className="card p-6 text-center">
          <div className="text-red-500 mb-2">⚠️ Error</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">{error}</div>
        </div>
      ) : loading ? (
        <div className="space-y-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="card p-4">
              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <div className="loading-skeleton w-8 h-8 rounded-lg" />
                  <div className="space-y-1">
                    <div className="loading-skeleton h-4 w-24" />
                    <div className="loading-skeleton h-3 w-16" />
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="loading-skeleton h-3 w-full" />
                  <div className="loading-skeleton h-3 w-3/4" />
                  <div className="loading-skeleton h-3 w-1/2" />
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-4">
          {blocks.map((block, index) => (
            <BlockCard
              key={block.hash}
              block={block}
              index={index}
            />
          ))}
        </div>
      )}
    </section>
  )
}
