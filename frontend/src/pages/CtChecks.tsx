import { Fragment, useCallback, useEffect, useState } from 'react'
import { api, CtCheckRecord, CtCheckResult } from '../api/client'
import { useAuth } from '../store/auth'
import HelpButton from '../components/HelpButton'
import CtCheckPanel, { CT_VERDICTS } from '../components/CtCheckPanel'

// Everyone with a login can read the history; only analysts and above can run a
// check, and only admins can have the server fetch a certificate from a host —
// the same power scan targets have.

const SOURCE_LABELS: Record<CtCheckRecord['source'], string> = {
  inventory: 'Inventory',
  pem: 'Pasted PEM',
  host: 'Fetched from host',
}

function fmtWhen(ts: string): string {
  const utc = ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z'
  return new Date(utc).toLocaleString([], { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export default function CtChecks() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const isAnalyst = isAdmin || user?.role === 'analyst'

  const [formOpen, setFormOpen] = useState(true)
  const [mode, setMode] = useState<'pem' | 'host'>('pem')
  const [pem, setPem] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('443')
  const [checking, setChecking] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<CtCheckResult | null>(null)

  const [history, setHistory] = useState<CtCheckRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [verdict, setVerdict] = useState('')
  const [open, setOpen] = useState<number | null>(null)
  const [detail, setDetail] = useState<CtCheckResult | null>(null)

  const load = useCallback(() => {
    api.getCtChecks({ search: search || undefined, verdict: verdict || undefined })
      .then(setHistory)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [search, verdict])

  useEffect(() => { load() }, [load])

  // Other people are running checks too — this is the shared record, so keep it
  // current without anyone having to reload.
  useEffect(() => {
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [load])

  const loadFile = async (f: File | null) => {
    if (f) setPem(await f.text())
  }

  const canRun = mode === 'pem' ? pem.trim().length > 0 : host.trim().length > 0

  const run = async () => {
    setChecking(true)
    setError('')
    setResult(null)
    try {
      setResult(await api.ctCheckAny(mode === 'pem' ? { pem } : { host: host.trim(), port: Number(port) || 443 }))
      load()
    } catch (e: any) {
      setError(e.message ?? 'Could not run the Certificate Transparency check')
    } finally {
      setChecking(false)
    }
  }

  const toggle = async (id: number) => {
    if (open === id) { setOpen(null); setDetail(null); return }
    setOpen(id)
    setDetail(null)
    try {
      setDetail((await api.getCtCheck(id)).result)
    } catch {
      setDetail(null)
    }
  }

  const c = result?.certificate

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <h1 className="text-xl font-bold text-white">CT Checks</h1>
        <HelpButton title="CT Checks — How It Works">
          <p>Validates a certificate against <span className="text-gray-300 font-medium">Certificate Transparency</span> logs through crt.sh: is it in the log, and has anything else been issued for its names that you don't know about?</p>
          <p>It works on <em>any</em> certificate, not only ones in the inventory. Paste or open a PEM; admins can also name a host and port and pktCert will fetch the certificate it presents.</p>
          <p>Every check is recorded below for all users to see — who ran it, on what, and the verdict — so nobody repeats a lookup that was already done. A PEM itself is never kept. Checks run from a certificate's detail view appear here too.</p>
          <p>The certificate's public DNS names are sent to crt.sh, a third-party service. Names that can't be public (.local, IP addresses, single labels) are not.</p>
        </HelpButton>
      </div>

      {isAnalyst ? (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3">
          <button onClick={() => setFormOpen(o => !o)} aria-expanded={formOpen}
            className="flex items-center gap-2 w-full text-left">
            <span className="text-xs text-white/70 w-3">{formOpen ? '▾' : '▸'}</span>
            <h2 className="text-sm font-semibold text-white">Check a certificate</h2>
          </button>
          {formOpen && (<>
          {isAdmin && (
            <div className="flex gap-2">
              <button onClick={() => setMode('pem')}
                className={`text-xs rounded px-3 py-1.5 border ${mode === 'pem' ? 'bg-gray-700 text-white border-gray-500' : 'bg-gray-800 text-white/70 border-gray-700'}`}>
                Paste or open a PEM
              </button>
              <button onClick={() => setMode('host')}
                className={`text-xs rounded px-3 py-1.5 border ${mode === 'host' ? 'bg-gray-700 text-white border-gray-500' : 'bg-gray-800 text-white/70 border-gray-700'}`}>
                Fetch from a host
              </button>
            </div>
          )}
          {mode === 'pem' ? (
            <div className="space-y-2">
              <textarea value={pem} onChange={e => setPem(e.target.value)} rows={7}
                placeholder="-----BEGIN CERTIFICATE-----"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-gray-600 resize-none" />
              <input type="file" accept=".pem,.crt,.cer" onChange={e => loadFile(e.target.files?.[0] ?? null)}
                className="block w-full text-sm text-white file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-gray-800 file:text-white hover:file:bg-gray-700 file:cursor-pointer" />
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex gap-2">
                <input value={host} onChange={e => setHost(e.target.value)} placeholder="host.example.com"
                  className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600" />
                <input value={port} onChange={e => setPort(e.target.value)} inputMode="numeric"
                  className="w-20 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white" />
              </div>
              <p className="text-xs text-white/70">pktCert connects to this host and port and reads the certificate it presents. Admin only.</p>
            </div>
          )}
          <div>
            <button onClick={run} disabled={checking || !canRun}
              className="text-sm bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg px-4 py-2 transition-colors">
              {checking ? 'Checking crt.sh…' : 'Validate with crt.sh'}
            </button>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          {result && c && (
            <div className="border-t border-gray-800 pt-3">
              <p className="text-xs text-white/70">Checked</p>
              <p className="text-sm text-white break-all">{c.common_name}{c.fetched_from ? ` (from ${c.fetched_from})` : ''}</p>
              <p className="text-xs text-white/70 font-mono break-all">{c.issuer}</p>
              <p className="text-xs text-white/70 mb-1">
                {result.in_inventory_id ? `Already in the inventory as #${result.in_inventory_id}` : 'Not in the inventory'}
              </p>
              <CtCheckPanel result={result} />
            </div>
          )}
          </>)}
        </div>
      ) : (
        <p className="text-sm text-white/70">Your role can read the history of checks but not run one. Analyst or higher is needed to check a certificate.</p>
      )}

      <div className="space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <h2 className="text-sm font-semibold text-white">Recent checks</h2>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search name, user, issuer, host…"
            className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white placeholder-gray-600 w-64 focus:outline-none focus:ring-1 focus:ring-sky-500" />
          <select value={verdict} onChange={e => setVerdict(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white focus:outline-none focus:ring-1 focus:ring-sky-500">
            <option value="">All results</option>
            {Object.entries(CT_VERDICTS).map(([v, { label }]) => <option key={v} value={v}>{label}</option>)}
          </select>
        </div>

        {loading ? (
          <p className="text-sm text-white">Loading…</p>
        ) : history.length === 0 ? (
          <p className="text-sm text-white/70">No checks yet.</p>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-white/70 border-b border-gray-800">
                  <th className="px-3 py-2 font-medium">When</th>
                  <th className="px-3 py-2 font-medium">Certificate</th>
                  <th className="px-3 py-2 font-medium">Source</th>
                  <th className="px-3 py-2 font-medium">By</th>
                  <th className="px-3 py-2 font-medium">Result</th>
                </tr>
              </thead>
              <tbody>
                {history.map(h => (
                  <Fragment key={h.id}>
                    <tr onClick={() => toggle(h.id)} className="border-b border-gray-800 hover:bg-gray-800/50 cursor-pointer">
                      <td className="px-3 py-2 text-white whitespace-nowrap">{fmtWhen(h.checked_at)}</td>
                      <td className="px-3 py-2 text-white">
                        <p className="break-all">{h.common_name || '—'}</p>
                        <p className="text-xs text-white/60 break-all">{h.issuer}</p>
                      </td>
                      <td className="px-3 py-2 text-white text-xs whitespace-nowrap">
                        {SOURCE_LABELS[h.source]}{h.fetched_from ? ` · ${h.fetched_from}` : ''}
                      </td>
                      <td className="px-3 py-2 text-white text-xs">{h.checked_by}</td>
                      <td className={`px-3 py-2 text-xs ${CT_VERDICTS[h.verdict]?.tone ?? 'text-white'}`}>
                        {CT_VERDICTS[h.verdict]?.label ?? h.verdict}
                        {h.unexpected_count > 0 && ` (${h.unexpected_count})`}
                      </td>
                    </tr>
                    {open === h.id && (
                      <tr className="border-b border-gray-800">
                        <td colSpan={5} className="px-3 py-3">
                          {detail ? <CtCheckPanel result={detail} /> : <p className="text-xs text-white/70">Loading…</p>}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
