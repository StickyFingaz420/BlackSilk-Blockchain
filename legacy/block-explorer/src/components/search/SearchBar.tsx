'use client'

import { useState } from 'react'
import { Search, Loader2 } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { parseSearchQuery } from '@/lib/utils'

export function SearchBar() {
  const [query, setQuery] = useState('')
  const [isSearching, setIsSearching] = useState(false)
  const router = useRouter()

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim() || isSearching) return

    setIsSearching(true)
    
    try {
      const parsed = parseSearchQuery(query.trim())
      
      switch (parsed.type) {
        case 'block':
          router.push(`/block/${parsed.value}`)
          break
        case 'transaction':
          router.push(`/tx/${parsed.value}`)
          break
        case 'address':
          router.push(`/address/${parsed.value}`)
          break
        default:
          router.push(`/search?q=${encodeURIComponent(parsed.value)}`)
      }
    } catch (error) {
      console.error('Search error:', error)
      // Could add toast notification here
    } finally {
      setIsSearching(false)
    }
  }

  const placeholder = "Search by block height, transaction hash, or address..."

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSearch} className="relative">
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
            <Search className="h-5 w-5 text-gray-400 dark:text-gray-500" />
          </div>
          
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            className="w-full pl-12 pr-16 py-4 text-lg border border-gray-300 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all duration-200 shadow-sm hover:shadow-md"
            disabled={isSearching}
          />
          
          <div className="absolute inset-y-0 right-0 pr-4 flex items-center">
            {isSearching ? (
              <Loader2 className="h-5 w-5 text-primary-500 animate-spin" />
            ) : (
              <button
                type="submit"
                disabled={!query.trim() || isSearching}
                className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors duration-200"
              >
                Search
              </button>
            )}
          </div>
        </div>
      </form>
      
      {/* Search suggestions */}
      <div className="mt-3 flex flex-wrap gap-2 justify-center">
        <span className="text-sm text-gray-500 dark:text-gray-400">Try:</span>
        {[
          { label: 'Block #1000', query: '1000' },
          { label: 'Latest Block', query: 'latest' },
          { label: 'Mempool', query: 'mempool' },
        ].map((suggestion) => (
          <button
            key={suggestion.label}
            onClick={() => setQuery(suggestion.query)}
            className="text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 underline-offset-2 hover:underline transition-colors duration-200"
          >
            {suggestion.label}
          </button>
        ))}
      </div>
    </div>
  )
}
