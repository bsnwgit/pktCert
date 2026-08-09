import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, DashboardSummary } from '../api/client'
import HelpButton from '../components/HelpButton'

function StatCard({ label, value, accent }: { label: string; value: string | number; accent?: string }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <p className="text-xs text-white uppercase tracking-wider">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${accent ?? 'text-white'}`}>{value}</p>
    </div>
  )
}

function fmtDate(ts: string): string {
  const utc = ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z'
  return new Date(utc).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
}

const STATUS_STYLES: Record<string, string> = {
  expiring: 'bg-amber-500/20 text-amber-400 border border-amber-500/40',
  expired: 'bg-red-500/20 text-red-400 border border-red-500/40',
}

export default function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getDashboardSummary().then(setSummary).finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="flex items-center justify-center h-48 text-white">Loading…</div>
  if (!summary) return null

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <h1 className="text-xl font-bold text-white">Dashboard</h1>
        <HelpButton title="Dashboard — How It Works">
          <p><span className="text-gray-300 font-medium">Total Certificates</span> covers every cert in the inventory — discovered by scan, found via Certificate Transparency search, or issued by an internal CA. <span className="text-gray-300 font-medium">Expiring Soon</span> and <span className="text-gray-300 font-medium">Active Alerts</span> both link through to their full pages.</p>
          <p>Expiring & Expired is a live shortcut — click a row to open that certificate's detail.</p>
        </HelpButton>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Certificates" value={summary.total} />
        <StatCard label="Expiring Soon" value={summary.expiring} accent={summary.expiring > 0 ? 'text-amber-400' : 'text-white'} />
        <StatCard label="Expired" value={summary.expired} accent={summary.expired > 0 ? 'text-red-400' : 'text-white'} />
        <StatCard label="Active Alerts" value={summary.active_alerts} accent={summary.active_alerts > 0 ? 'text-red-400' : 'text-white'} />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Certificate Authorities" value={summary.ca_count} />
        <StatCard label="Scan Targets (enabled)" value={summary.scan_targets} />
        <StatCard label="Issued Internally" value={summary.issued} />
        <StatCard label="Discovered by Scan" value={summary.scanned} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Expiring & Expired</h2>
            <Link to="/certificates?status=expiring" className="text-xs text-sky-400 hover:text-sky-300">View all →</Link>
          </div>
          <div className="divide-y divide-gray-800/60">
            {summary.expiring_soon.length === 0 && (
              <p className="text-sm text-white p-4">Nothing expiring in the next 30 days.</p>
            )}
            {summary.expiring_soon.map(c => (
              <Link key={c.id} to={`/certificates?search=${encodeURIComponent(c.common_name)}`} className="block px-4 py-3 hover:bg-gray-800/30 transition-colors">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm text-white font-mono truncate">{c.common_name}</span>
                  <span className={`shrink-0 text-xs px-2 py-0.5 rounded-full font-medium capitalize ${STATUS_STYLES[c.status] ?? ''}`}>{c.status}</span>
                </div>
                <p className="text-xs text-white mt-0.5">Expires {fmtDate(c.not_after)}</p>
              </Link>
            ))}
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Inventory by Status</h2>
            <Link to="/certificates" className="text-xs text-sky-400 hover:text-sky-300">View all →</Link>
          </div>
          <div className="p-4 space-y-3">
            {[
              { label: 'Valid', value: summary.valid, color: 'bg-emerald-500' },
              { label: 'Expiring', value: summary.expiring, color: 'bg-amber-500' },
              { label: 'Expired', value: summary.expired, color: 'bg-red-500' },
              { label: 'Revoked', value: summary.revoked, color: 'bg-gray-500' },
            ].map(row => (
              <div key={row.label}>
                <div className="flex items-center justify-between text-sm mb-1">
                  <span className="text-white">{row.label}</span>
                  <span className="text-white">{row.value}</span>
                </div>
                <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                  <div className={`h-full ${row.color}`} style={{ width: summary.total ? `${Math.min(100, (row.value / summary.total) * 100)}%` : '0%' }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {summary.total === 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center text-sm text-white">
          No certificates yet. Add a Scan Target to discover certs on your network, or generate a
          Certificate Authority under Certificate Authorities to start issuing your own.
        </div>
      )}
    </div>
  )
}
