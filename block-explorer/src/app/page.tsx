import { NetworkStats } from '@/components/dashboard/NetworkStats'
import { RecentBlocks } from '@/components/dashboard/RecentBlocks'
import { RecentTransactions } from '@/components/dashboard/RecentTransactions'
import { SearchBar } from '@/components/search/SearchBar'
import { Hero } from '@/components/dashboard/Hero'

export default function HomePage() {
  return (
    <div className="container mx-auto px-4 py-8 space-y-8">
      <Hero />
      
      <div className="max-w-2xl mx-auto">
        <SearchBar />
      </div>

      <NetworkStats />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <RecentBlocks />
        <RecentTransactions />
      </div>
    </div>
  )
}
