import { type ClassValue, clsx } from 'clsx'

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs)
}

// Format numbers with appropriate suffixes
export function formatNumber(num: number): string {
  if (num >= 1e9) return (num / 1e9).toFixed(2) + 'B'
  if (num >= 1e6) return (num / 1e6).toFixed(2) + 'M'
  if (num >= 1e3) return (num / 1e3).toFixed(2) + 'K'
  return num.toLocaleString()
}

// Format BLK amounts
export function formatBLK(amount: number, decimals: number = 8): string {
  const blk = amount / Math.pow(10, decimals)
  return blk.toFixed(decimals).replace(/\.?0+$/, '') + ' BLK'
}

// Format file sizes
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// Format time ago
export function formatTimeAgo(timestamp: number): string {
  const now = Date.now() / 1000
  const diff = now - timestamp
  
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  if (diff < 2592000) return `${Math.floor(diff / 86400)}d ago`
  if (diff < 31536000) return `${Math.floor(diff / 2592000)}mo ago`
  return `${Math.floor(diff / 31536000)}y ago`
}

// Format timestamp to date
export function formatDate(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString()
}

// Format hash with ellipsis
export function formatHash(hash: string, start: number = 8, end: number = 8): string {
  if (hash.length <= start + end) return hash
  return `${hash.slice(0, start)}...${hash.slice(-end)}`
}

// Format address for display
export function formatAddress(address: string, start: number = 6, end: number = 6): string {
  if (address.length <= start + end) return address
  return `${address.slice(0, start)}...${address.slice(-end)}`
}

// Copy to clipboard
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch (err) {
    // Fallback for older browsers
    const textArea = document.createElement('textarea')
    textArea.value = text
    document.body.appendChild(textArea)
    textArea.focus()
    textArea.select()
    try {
      document.execCommand('copy')
      return true
    } catch (err) {
      console.error('Failed to copy text: ', err)
      return false
    } finally {
      document.body.removeChild(textArea)
    }
  }
}

// Validate hash format
export function isValidHash(hash: string): boolean {
  return /^[a-fA-F0-9]{64}$/.test(hash)
}

// Validate address format (simplified)
export function isValidAddress(address: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{25,}$/.test(address)
}

// Validate transaction ID
export function isValidTxId(txid: string): boolean {
  return isValidHash(txid)
}

// Generate QR code data URL
export function generateQRCode(text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    import('qrcode').then(QRCode => {
      QRCode.toDataURL(text, {
        width: 256,
        margin: 2,
        color: {
          dark: '#000000',
          light: '#FFFFFF'
        }
      }, (err: any, url: string) => {
        if (err) reject(err)
        else resolve(url)
      })
    }).catch(reject)
  })
}

// Calculate difficulty adjustment
export function calculateNextDifficulty(
  currentDifficulty: number,
  expectedTime: number,
  actualTime: number,
  maxAdjustment: number = 4
): number {
  const ratio = expectedTime / actualTime
  const adjustmentFactor = Math.max(1 / maxAdjustment, Math.min(maxAdjustment, ratio))
  return Math.floor(currentDifficulty * adjustmentFactor)
}

// Format hashrate
export function formatHashrate(hashrate: number): string {
  const units = ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s']
  let index = 0
  let rate = hashrate
  
  while (rate >= 1000 && index < units.length - 1) {
    rate /= 1000
    index++
  }
  
  return `${rate.toFixed(2)} ${units[index]}`
}

// Parse search query to determine type
export function parseSearchQuery(query: string): {
  type: 'block' | 'transaction' | 'address' | 'unknown'
  value: string
} {
  const trimmed = query.trim()
  
  // Check if it's a number (block height)
  if (/^\d+$/.test(trimmed)) {
    return { type: 'block', value: trimmed }
  }
  
  // Check if it's a hash (64 hex characters)
  if (isValidHash(trimmed)) {
    return { type: 'transaction', value: trimmed }
  }
  
  // Check if it's an address
  if (isValidAddress(trimmed)) {
    return { type: 'address', value: trimmed }
  }
  
  return { type: 'unknown', value: trimmed }
}

// Debounce function
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null
  
  return (...args: Parameters<T>) => {
    if (timeout) clearTimeout(timeout)
    timeout = setTimeout(() => func(...args), wait)
  }
}

// Throttle function
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean
  
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args)
      inThrottle = true
      setTimeout(() => inThrottle = false, limit)
    }
  }
}

// Calculate percentage change
export function calculatePercentageChange(current: number, previous: number): number {
  if (previous === 0) return 0
  return ((current - previous) / previous) * 100
}

// Format percentage
export function formatPercentage(value: number, decimals: number = 2): string {
  return `${value.toFixed(decimals)}%`
}

// Get difficulty color based on change
export function getDifficultyColor(change: number): string {
  if (change > 0) return 'text-green-500'
  if (change < 0) return 'text-red-500'
  return 'text-gray-500'
}

// Get privacy level color
export function getPrivacyLevelColor(level: string): string {
  switch (level) {
    case 'private': return 'text-purple-500'
    case 'stealth': return 'text-indigo-500'
    case 'public': default: return 'text-gray-500'
  }
}

// Get transaction type color
export function getTransactionTypeColor(type: string): string {
  switch (type) {
    case 'coinbase': return 'text-yellow-500'
    case 'transfer': return 'text-blue-500'
    case 'privacy': return 'text-purple-500'
    case 'escrow': return 'text-green-500'
    default: return 'text-gray-500'
  }
}
