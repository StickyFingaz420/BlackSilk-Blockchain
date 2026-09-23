'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { 
  Activity, 
  Blocks, 
  Users, 
  Zap, 
  TrendingUp, 
  Clock,
  Coins,
  Shield
} from 'lucide-react'
import api from '@/lib/api'
import { formatNumber, formatHashrate, formatTimeAgo } from '@/lib/utils'
import type { NetworkInfo } from '@/types'

interface StatCardProps {
  title: string
  value: string | number
  change?: number
  icon: React.ReactNode
  loading?: boolean
  subtitle?: string
}

function StatCard({ title, value, change, icon, loading, subtitle }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="stat-card hover:shadow-lg transition-shadow duration-300"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30 text-primary-600 dark:text-primary-400">
            {icon}
          </div>
          <div>
            <div className="stat-label">{title}</div>
            {subtitle && (
              <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                {subtitle}
              </div>
            )}
          </div>
        </div>
        {change !== undefined && (
          <div className={`text-sm font-medium ${
            change > 0 ? 'text-green-500' : change < 0 ? 'text-red-500' : 'text-gray-500'
          }`}>
            {change > 0 ? '+' : ''}{change.toFixed(2)}%
          </div>
        )}
      </div>
      
      <div className="mt-2">
        {loading ? (
          <div className="loading-skeleton h-8 w-24" />
        ) : (
          <div className="stat-value">{value}</div>
        )}
      </div>
    </motion.div>
  )
}

export function NetworkStats() {
  const [stats, setStats] = useState<NetworkInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const networkInfo = await api.getNetworkInfo()
        setStats(networkInfo)
        setError(null)
      } catch (err) {
        console.error('Failed to fetch network stats:', err)
        setError('Failed to load network statistics')
      } finally {
        setLoading(false)
      }
    }

    fetchStats()
    
    // Update stats every 30 seconds
    const interval = setInterval(fetchStats, 30000)
    return () => clearInterval(interval)
  }, [])

  if (error) {
    return (
      <div className="card p-6 text-center">
        <div className="text-red-500 mb-2">⚠️ Network Connection Error</div>
        <div className="text-sm text-gray-600 dark:text-gray-400">{error}</div>
      </div>
    )
  }

  const statsData = [
    {
      title: 'Block Height',
      value: loading ? '...' : formatNumber(stats?.height || 0),
      icon: <Blocks className="w-5 h-5" />,
      subtitle: `~${Math.floor((stats?.height || 0) * 2 / 60)} hours of uptime`
    },
    {
      title: 'Difficulty',
      value: loading ? '...' : formatNumber(stats?.difficulty || 0),
      icon: <TrendingUp className="w-5 h-5" />,
      subtitle: `Adjusts every 60 blocks`
    },
    {
      title: 'Network Hashrate',
      value: loading ? '...' : formatHashrate(stats?.hashrate || 0),
      icon: <Zap className="w-5 h-5" />,
      subtitle: 'RandomX algorithm'
    },
    {
      title: 'Connected Peers',
      value: loading ? '...' : formatNumber(stats?.peers || 0),
      icon: <Users className="w-5 h-5" />,
      subtitle: 'Active network nodes'
    },
    {
      title: 'Mempool Size',
      value: loading ? '...' : formatNumber(stats?.mempool_size || 0),
      icon: <Activity className="w-5 h-5" />,
      subtitle: 'Pending transactions'
    },
    {
      title: 'Block Time',
      value: loading ? '...' : `${stats?.block_time || 120}s`,
      icon: <Clock className="w-5 h-5" />,
      subtitle: 'Target: 2 minutes'
    },
    {
      title: 'Current Reward',
      value: loading ? '...' : `${stats?.mining.current_reward || 5} BLK`,
      icon: <Coins className="w-5 h-5" />,
      subtitle: 'Per block mined'
    },
    {
      title: 'Circulating Supply',
      value: loading ? '...' : `${formatNumber(stats?.supply.circulating || 0)} BLK`,
      icon: <Shield className="w-5 h-5" />,
      subtitle: `Cap: ${formatNumber(stats?.supply.total_cap || 21000000)} BLK`
    }
  ]

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Network Statistics
        </h2>
        <div className="flex items-center space-x-2 text-sm text-gray-500 dark:text-gray-400">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span>Live data</span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsData.map((stat, index) => (
          <StatCard
            key={stat.title}
            title={stat.title}
            value={stat.value}
            icon={stat.icon}
            loading={loading}
            subtitle={stat.subtitle}
          />
        ))}
      </div>

      {/* Additional Network Info */}
      {stats && !loading && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="card p-6"
        >
          <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
            Network Information
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div>
              <span className="text-gray-500 dark:text-gray-400">Version:</span>
              <span className="ml-2 font-mono text-gray-900 dark:text-white">
                {stats.version}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Network:</span>
              <span className="ml-2 font-medium text-primary-600 dark:text-primary-400">
                {stats.network}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Algorithm:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-white">
                {stats.mining.algorithm}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Best Block:</span>
              <span className="ml-2 font-mono text-xs text-gray-900 dark:text-white">
                {stats.best_block_hash.slice(0, 16)}...
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Next Halving:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-white">
                Block #{formatNumber(stats.mining.next_halving)}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Burned Supply:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-white">
                {formatNumber(stats.supply.burned)} BLK
              </span>
            </div>
          </div>
        </motion.div>
      )}
    </section>
  )
}
