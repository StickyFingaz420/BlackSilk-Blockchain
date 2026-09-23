'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { ArrowRight, Send, Shield, Eye, Coins } from 'lucide-react'
import api from '@/lib/api'
import { formatTimeAgo, formatBLK, formatHash, getTransactionTypeColor, getPrivacyLevelColor } from '@/lib/utils'
import type { Transaction } from '@/types'

interface TransactionCardProps {
  transaction: Transaction
  index: number
}

function TransactionCard({ transaction, index }: TransactionCardProps) {
  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'coinbase': return <Coins className="w-4 h-4" />
      case 'privacy': return <Shield className="w-4 h-4" />
      case 'escrow': return <Eye className="w-4 h-4" />
      default: return <Send className="w-4 h-4" />
    }
  }

  const totalOutput = transaction.outputs.reduce((sum, output) => sum + output.value, 0)

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.5, delay: index * 0.1 }}
    >
      <Link
        href={`/tx/${transaction.txid}`}
        className="block card p-4 hover:shadow-lg transition-all duration-300 hover:scale-105"
      >
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
              transaction.type === 'coinbase' ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400' :
              transaction.type === 'privacy' ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400' :
              transaction.type === 'escrow' ? 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400' :
              'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
            }`}>
              {getTypeIcon(transaction.type)}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-semibold text-gray-900 dark:text-white capitalize">
                  {transaction.type}
                </span>
                {transaction.privacy_level && transaction.privacy_level !== 'public' && (
                  <span className={`text-xs px-2 py-1 rounded-full bg-purple-100 dark:bg-purple-900/30 ${getPrivacyLevelColor(transaction.privacy_level)}`}>
                    {transaction.privacy_level}
                  </span>
                )}
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">
                {transaction.inputs.length} inputs → {transaction.outputs.length} outputs
              </div>
            </div>
          </div>
          <ArrowRight className="w-4 h-4 text-gray-400 dark:text-gray-500" />
        </div>

        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-500 dark:text-gray-400">TxID:</span>
            <span className="font-mono text-gray-900 dark:text-white">
              {formatHash(transaction.txid, 6, 6)}
            </span>
          </div>
          
          <div className="flex justify-between">
            <span className="text-gray-500 dark:text-gray-400">Amount:</span>
            <span className="text-gray-900 dark:text-white font-medium">
              {formatBLK(totalOutput)}
            </span>
          </div>
          
          <div className="flex justify-between">
            <span className="text-gray-500 dark:text-gray-400">Time:</span>
            <span className="text-gray-900 dark:text-white">
              {formatTimeAgo(transaction.timestamp)}
            </span>
          </div>

          {transaction.fee && (
            <div className="flex justify-between">
              <span className="text-gray-500 dark:text-gray-400">Fee:</span>
              <span className="text-gray-900 dark:text-white">
                {formatBLK(transaction.fee)}
              </span>
            </div>
          )}

          {transaction.ring_size && (
            <div className="flex justify-between">
              <span className="text-gray-500 dark:text-gray-400">Ring Size:</span>
              <span className="text-purple-600 dark:text-purple-400 font-medium">
                {transaction.ring_size}
              </span>
            </div>
          )}

          {transaction.confirmations !== undefined && (
            <div className="flex justify-between">
              <span className="text-gray-500 dark:text-gray-400">Confirmations:</span>
              <span className={`font-medium ${
                transaction.confirmations >= 10 ? 'text-green-600 dark:text-green-400' :
                transaction.confirmations >= 1 ? 'text-yellow-600 dark:text-yellow-400' :
                'text-red-600 dark:text-red-400'
              }`}>
                {transaction.confirmations}
              </span>
            </div>
          )}
        </div>
      </Link>
    </motion.div>
  )
}

export function RecentTransactions() {
  const [transactions, setTransactions] = useState<Transaction[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchTransactions = async () => {
      try {
        // Get recent blocks and extract transactions
        const blocks = await api.getLatestBlocks(3)
        const recentTxs: Transaction[] = []
        
        blocks.forEach(block => {
          block.transactions.forEach(tx => {
            recentTxs.push({
              ...tx,
              block_height: block.height,
              confirmations: 1 // Simplified for display
            })
          })
        })
        
        // Sort by timestamp and take latest 5
        recentTxs.sort((a, b) => b.timestamp - a.timestamp)
        setTransactions(recentTxs.slice(0, 5))
        setError(null)
      } catch (err) {
        console.error('Failed to fetch recent transactions:', err)
        setError('Failed to load recent transactions')
      } finally {
        setLoading(false)
      }
    }

    fetchTransactions()
    
    // Update transactions every 30 seconds
    const interval = setInterval(fetchTransactions, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white">
          Recent Transactions
        </h2>
        <Link
          href="/transactions"
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
                    <div className="loading-skeleton h-4 w-20" />
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
      ) : transactions.length === 0 ? (
        <div className="card p-6 text-center">
          <div className="text-gray-500 dark:text-gray-400 mb-2">📭 No recent transactions</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">
            Transactions will appear here once blocks are mined
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {transactions.map((transaction, index) => (
            <TransactionCard
              key={transaction.txid}
              transaction={transaction}
              index={index}
            />
          ))}
        </div>
      )}
    </section>
  )
}
