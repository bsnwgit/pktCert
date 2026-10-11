import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

// Small strip above the page when a newer release exists. A fresh load asks
// the backend; once an update is showing nothing asks again. If the page stays
// open it asks once every 24 hours. Any failure just means no banner — it is a
// hint, never an error.

interface UpdateStatus {
  current_version: string
  latest_tag: string | null
  update_available: boolean
}

const DAY_MS = 24 * 60 * 60 * 1000

export default function UpdateBanner() {
  const [st, setSt] = useState<UpdateStatus | null>(null)
  const showing = useRef(false)

  useEffect(() => {
    let live = true
    const load = () => {
      if (showing.current) return
      fetch('/api/system/update-banner')
        .then(res => (res.ok ? res.json() : null))
        .then(s => {
          if (live && s) {
            showing.current = !!s.update_available
            setSt(s)
          }
        })
        .catch(() => {})
    }
    load()
    const id = setInterval(load, DAY_MS)
    return () => { live = false; clearInterval(id) }
  }, [])

  if (!st?.update_available) return null

  return (
    <div role="status" className="flex-shrink-0 flex items-center gap-3 border-b border-gray-800 bg-gray-900 px-4 py-1.5 text-xs text-yellow-400">
      <span>Update available: {st.latest_tag} (you have v{st.current_version})</span>
      <Link to="/settings?tab=system" className="ml-auto text-blue-400 hover:text-blue-300 underline">View</Link>
    </div>
  )
}
