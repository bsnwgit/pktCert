import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

// Small strip above the page when a newer release exists. Loading the app asks
// the backend to re-check GitHub (rate-limited server-side, so a busy page is
// not a flood), instead of waiting for the hourly checker. Any failure just
// means no banner — it is a hint, never an error.

interface UpdateStatus {
  current_version: string
  latest_tag: string | null
  update_available: boolean
}

export default function UpdateBanner() {
  const [st, setSt] = useState<UpdateStatus | null>(null)

  useEffect(() => {
    let live = true
    fetch('/api/system/update-banner')
      .then(res => (res.ok ? res.json() : null))
      .then(s => { if (live && s) setSt(s) })
      .catch(() => {})
    return () => { live = false }
  }, [])

  if (!st?.update_available) return null

  return (
    <div role="status" className="flex-shrink-0 flex items-center gap-3 border-b border-gray-800 bg-gray-900 px-4 py-1.5 text-xs text-yellow-400">
      <span>Update available: {st.latest_tag} (you have v{st.current_version})</span>
      <Link to="/settings?tab=system" className="ml-auto text-blue-400 hover:text-blue-300 underline">View</Link>
    </div>
  )
}
