import { Fragment, useEffect, useState } from 'react'
import { api, AppLog, LogStats } from '../api/client'
import { useAuth } from '../store/auth'
import TimeRangeControl, { TimeRange } from '../components/TimeRangeControl'
import HelpButton from '../components/HelpButton'

const LEVELS = ['ALL', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
const PAGE_SIZE_OPTIONS = [25, 50, 75, 100]

const LEVEL_COLOR: Record<string, string> = {
  DEBUG: 'text-white', INFO: 'text-sky-400', WARNING: 'text-amber-400',
  ERROR: 'text-red-400', CRITICAL: 'text-red-400',
}

export default function Logs() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [level, setLevel] = useState('ALL')
  const [logger, setLogger] = useState('')
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [timeRange, setTimeRange] = useState<TimeRange>({ since: null, until: null })
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [expanded, setExpanded] = useState<number | null>(null)

  const [logs, setLogs] = useState<AppLog[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState<LogStats | null>(null)

  const [levelSaving, setLevelSaving] = useState(false)
  const [clearing, setClearing] = useState(false)

  const load = (silent = false) => {
    if (!silent) setLoading(true)
    api.getAppLogs({
      level: level === 'ALL' ? undefined : level,
      logger: logger || undefined,
      search: search || undefined,
      since: timeRange.since, until: timeRange.until,
      limit: pageSize, offset: (page - 1) * pageSize,
    }).then(res => { setLogs(res.records); setTotal(res.total) }).finally(() => setLoading(false))
  }

  const loadStats = () => { api.getLogStats().then(setStats).catch(() => {}) }

  useEffect(load, [level, logger, search, timeRange, page, pageSize])
  useEffect(loadStats, [])
  useEffect(() => { setPage(1) }, [level, logger, search, timeRange])

  useEffect(() => {
    if (!autoRefresh) return
    const id = setInterval(() => { load(true); loadStats() }, 5000)
    return () => clearInterval(id)
  }, [autoRefresh, level, logger, search, timeRange, page, pageSize])

  const changePageSize = (size: number) => {
    setPageSize(size)
    setPage(1)
  }

  const setCaptureLevel = async (newLevel: string) => {
    setLevelSaving(true)
    try { await api.setLogCaptureLevel(newLevel); loadStats() } finally { setLevelSaving(false) }
  }

  const clearLogs = async () => {
    if (!confirm('Delete all application logs? This cannot be undone.')) return
    setClearing(true)
    try { await api.clearLogs(); load(); loadStats() } finally { setClearing(false) }
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-white">Application Logs</h1>
          <HelpButton title="Application Logs — How It Works">
            <p>This is the app's own internal log, not certificate data — scan runs, API errors, and background job activity.</p>
            <p>Capture level controls how much is written going forward (admin-only) — lowering it to DEBUG is useful when troubleshooting a specific scan target, but generates far more volume.</p>
          </HelpButton>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-white">
            <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} /> Auto-refresh (5s)
          </label>
          <button onClick={() => { load(); loadStats() }} className="text-xs text-white border border-gray-700 rounded-lg px-3 py-1.5 hover:bg-gray-800">Reload</button>
          {isAdmin && (
            <button onClick={clearLogs} disabled={clearing} className="text-xs text-red-400 border border-red-800/60 rounded-lg px-3 py-1.5 hover:bg-red-900/20 disabled:opacity-50">
              {clearing ? 'Clearing…' : 'Clear Logs'}
            </button>
          )}
        </div>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-3">
            <p className="text-xs text-white uppercase">Total</p>
            <p className="text-lg font-bold text-white">{stats.total.toLocaleString()}</p>
          </div>
          {['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'].map(lvl => (
            <div key={lvl} className="bg-gray-900 border border-gray-800 rounded-xl p-3">
              <p className="text-xs text-white uppercase">{lvl}</p>
              <p className={`text-lg font-bold ${LEVEL_COLOR[lvl]}`}>{(stats.by_level[lvl] ?? 0).toLocaleString()}</p>
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        {LEVELS.map(l => (
          <button key={l} onClick={() => setLevel(l)}
            className={`text-xs px-3 py-1.5 rounded-lg border ${level === l ? 'bg-gray-700 border-gray-600 text-white' : 'bg-gray-900 border-gray-800 text-white hover:bg-gray-800'}`}>
            {l}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <select value={logger} onChange={e => setLogger(e.target.value)} className="bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-2.5 py-1.5">
          <option value="">All loggers</option>
          {(stats?.loggers ?? []).map(lg => <option key={lg} value={lg}>{lg}</option>)}
        </select>
        <input
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') setSearch(searchInput) }}
          placeholder="Search message… (Enter)"
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 w-64"
        />
        {searchInput && (
          <button onClick={() => { setSearchInput(''); setSearch('') }} className="text-xs text-white hover:text-white">✕</button>
        )}
        <TimeRangeControl value={timeRange} onChange={setTimeRange} />
        {isAdmin && stats && (
          <div className="flex items-center gap-2 ml-auto">
            <span className="text-xs text-white">Capture level:</span>
            <select value={stats.capture_level} onChange={e => setCaptureLevel(e.target.value)} disabled={levelSaving}
              className="bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-2.5 py-1.5">
              {['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'].map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
        )}
      </div>

      {loading ? <div className="text-white text-sm">Loading…</div> : (
        <>
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-6">
              <div className="flex items-center gap-2">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  className="text-xs text-white border border-gray-700 rounded-lg px-3 py-1.5 hover:bg-gray-800 disabled:opacity-40">Prev</button>
                <span className="text-xs text-white">Page {page} of {totalPages}</span>
                <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                  className="text-xs text-white border border-gray-700 rounded-lg px-3 py-1.5 hover:bg-gray-800 disabled:opacity-40">Next</button>
              </div>
              <div className="flex items-center gap-2">
                <label htmlFor="logs-per-page" className="text-xs text-gray-400">Logs per page:</label>
                <select
                  id="logs-per-page"
                  value={pageSize}
                  onChange={e => changePageSize(Number(e.target.value))}
                  className="text-sm bg-gray-800 border border-gray-700 text-white rounded-lg px-2 py-1 focus:outline-none focus:border-sky-500"
                >
                  {PAGE_SIZE_OPTIONS.map(size => (
                    <option key={size} value={size}>{size}</option>
                  ))}
                </select>
              </div>
            </div>
          )}

          <div className="f-tbl-scroll bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full text-sm font-mono">
              <thead>
                <tr className="border-b border-gray-800 font-sans">
                  <th className="text-left px-3 py-2 text-xs font-medium text-white uppercase tracking-wider">Timestamp</th>
                  <th className="text-left px-3 py-2 text-xs font-medium text-white uppercase tracking-wider">Level</th>
                  <th className="text-left px-3 py-2 text-xs font-medium text-white uppercase tracking-wider">Logger</th>
                  <th className="text-left px-3 py-2 text-xs font-medium text-white uppercase tracking-wider">Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(l => (
                  <Fragment key={l.id}>
                    <tr className={`border-t border-gray-800 align-top ${l.exc_info ? 'cursor-pointer hover:bg-gray-800/30' : ''}`}
                      onClick={() => l.exc_info && setExpanded(expanded === l.id ? null : l.id)}>
                      <td className="px-3 py-1.5 text-white whitespace-nowrap">{l.created_at}</td>
                      <td className={`px-3 py-1.5 whitespace-nowrap ${LEVEL_COLOR[l.level] ?? 'text-white'}`}>{l.level}</td>
                      <td className="px-3 py-1.5 text-white whitespace-nowrap">{l.logger.replace(/^pktcert\.?/, '')}</td>
                      <td className="px-3 py-1.5 text-white">{l.message}{l.exc_info && <span className="text-sky-400 ml-2 text-xs">[stack trace ▾]</span>}</td>
                    </tr>
                    {expanded === l.id && l.exc_info && (
                      <tr className="border-t border-gray-800">
                        <td colSpan={4} className="px-3 py-2 bg-gray-950">
                          <pre className="text-xs text-red-300 whitespace-pre-wrap">{l.exc_info}</pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
                {logs.length === 0 && (
                  <tr><td colSpan={4} className="px-4 py-8 text-center text-white font-sans">No log entries match this filter.</td></tr>
                )}
              </tbody>
            </table>
          </div>

          <p className="text-xs text-white">
            {total === 0 ? '0 records' : `Showing ${(page - 1) * pageSize + 1}–${Math.min(page * pageSize, total)} of ${total.toLocaleString()}`}
            {autoRefresh && <span className="ml-2 text-emerald-400">● live</span>}
          </p>
        </>
      )}
    </div>
  )
}
