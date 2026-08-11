import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, ScanTarget } from '../api/client'
import { useAuth } from '../store/auth'
import HelpButton from '../components/HelpButton'
import Pagination from '../components/Pagination'

const PAGE_SIZE_DEFAULT = 25
const PAGE_SIZE_OPTIONS = [25, 50, 75, 100]

const STATUS_STYLES: Record<string, string> = {
  ok: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40',
  error: 'bg-red-500/20 text-red-400 border border-red-500/40',
  unknown: 'bg-gray-500/20 text-gray-400 border border-gray-500/40',
}

interface FormData {
  name: string
  mode: 'host' | 'cidr'
  host: string
  cidr: string
  ports: string
  schedule_minutes: string
  enabled: boolean
}

const EMPTY: FormData = { name: '', mode: 'host', host: '', cidr: '', ports: '443', schedule_minutes: '1440', enabled: true }

function fromTarget(t: ScanTarget): FormData {
  return {
    name: t.name, mode: t.cidr ? 'cidr' : 'host', host: t.host ?? '', cidr: t.cidr ?? '',
    ports: t.ports, schedule_minutes: String(t.schedule_minutes), enabled: t.enabled,
  }
}

function TargetForm({ initial, onSave, onCancel, saving }: {
  initial: FormData
  onSave: (data: FormData) => Promise<void>
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState<FormData>(initial)
  const set = <K extends keyof FormData>(k: K, v: FormData[K]) => setForm(f => ({ ...f, [k]: v }))
  const inp = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500'

  return (
    <div className="bg-gray-900 border border-sky-500/30 rounded-xl p-5 space-y-4">
      <h3 className="text-sm font-semibold text-white">{initial.name ? 'Edit scan target' : 'New scan target'}</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="sm:col-span-2">
          <label className="block text-xs text-white mb-1">Name</label>
          <input value={form.name} onChange={e => set('name', e.target.value)} placeholder="Prod web tier" className={inp} />
        </div>
        <div>
          <label className="block text-xs text-white mb-1">Target type</label>
          <select value={form.mode} onChange={e => set('mode', e.target.value as 'host' | 'cidr')} className={inp}>
            <option value="host">Single host</option>
            <option value="cidr">CIDR range</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-white mb-1">{form.mode === 'host' ? 'Host' : 'CIDR'}</label>
          {form.mode === 'host' ? (
            <input value={form.host} onChange={e => set('host', e.target.value)} placeholder="host.example.com" className={inp} />
          ) : (
            <input value={form.cidr} onChange={e => set('cidr', e.target.value)} placeholder="10.0.1.0/24" className={inp} />
          )}
        </div>
        <div>
          <label className="block text-xs text-white mb-1">Ports (comma-separated)</label>
          <input value={form.ports} onChange={e => set('ports', e.target.value)} placeholder="443,8443" className={inp} />
        </div>
        <div>
          <label className="block text-xs text-white mb-1">Scan interval (minutes, 0 = manual only)</label>
          <input type="number" min={0} value={form.schedule_minutes} onChange={e => set('schedule_minutes', e.target.value)} className={inp} />
        </div>
      </div>
      <label className="flex items-center gap-2 text-sm text-white">
        <input type="checkbox" checked={form.enabled} onChange={e => set('enabled', e.target.checked)} className="rounded border-gray-700 bg-gray-800" />
        Enabled
      </label>
      <div className="flex items-center gap-3 pt-1">
        <button onClick={() => onSave(form)} disabled={saving || !form.name.trim() || (form.mode === 'host' ? !form.host.trim() : !form.cidr.trim())}
          className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
          {saving ? 'Saving…' : 'Save'}
        </button>
        <button onClick={onCancel} className="text-white hover:text-white text-sm border border-gray-700 rounded-lg px-4 py-2 transition-colors">Cancel</button>
      </div>
    </div>
  )
}

export default function ScanTargets() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [targets, setTargets] = useState<ScanTarget[]>([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(PAGE_SIZE_DEFAULT)
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<ScanTarget | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [scanningId, setScanningId] = useState<number | null>(null)
  const [scanResult, setScanResult] = useState<{ id: number; text: string } | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try { setTargets(await api.getScanTargets()) } finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const handleSave = async (form: FormData) => {
    setSaving(true)
    setError('')
    try {
      const body = {
        name: form.name,
        host: form.mode === 'host' ? form.host : null,
        cidr: form.mode === 'cidr' ? form.cidr : null,
        ports: form.ports || '443',
        schedule_minutes: parseInt(form.schedule_minutes) || 0,
        enabled: form.enabled,
      }
      if (editing) {
        await api.updateScanTarget(editing.id, body)
        setEditing(null)
      } else {
        await api.createScanTarget(body)
        setAdding(false)
      }
      await load()
    } catch (e: any) {
      setError(e.message ?? 'Failed to save scan target')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (t: ScanTarget) => {
    if (!confirm(`Delete scan target "${t.name}"?`)) return
    await api.deleteScanTarget(t.id)
    await load()
  }

  const handleScanNow = async (t: ScanTarget) => {
    setScanningId(t.id)
    try {
      const r = await api.scanTargetNow(t.id)
      setScanResult({ id: t.id, text: `Scanned ${r.hosts_scanned} host:port pair(s), found ${r.certificates_found} certificate(s)${r.errors ? `, ${r.errors} unreachable` : ''}.` })
      await load()
    } catch (e: any) {
      setScanResult({ id: t.id, text: e.message ?? 'Scan failed' })
    } finally {
      setScanningId(null)
    }
  }

  const totalPages = Math.max(1, Math.ceil(targets.length / pageSize))
  const pageClamped = Math.min(page, totalPages)
  const paged = useMemo(
    () => targets.slice((pageClamped - 1) * pageSize, pageClamped * pageSize),
    [targets, pageClamped, pageSize],
  )
  const firstShown = targets.length === 0 ? 0 : (pageClamped - 1) * pageSize + 1
  const lastShown = (pageClamped - 1) * pageSize + paged.length

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-white">Scan Targets</h1>
          <HelpButton title="Scan Targets — How It Works">
            <p>Each target is a host or CIDR range plus a port list. On its schedule (or on-demand via "Scan Now"), pktCert connects via TLS to every host:port pair and records the live certificate into the inventory.</p>
            <p>A CIDR scan is capped at 4096 addresses per run to avoid an accidental fat-fingered range taking down the scan engine.</p>
          </HelpButton>
        </div>
        {isAdmin && !adding && !editing && (
          <button onClick={() => setAdding(true)}
            className="bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors">
            + New target
          </button>
        )}
      </div>

      {adding && <TargetForm initial={EMPTY} onSave={handleSave} onCancel={() => setAdding(false)} saving={saving} />}
      {editing && <TargetForm initial={fromTarget(editing)} onSave={handleSave} onCancel={() => setEditing(null)} saving={saving} />}
      {error && <p className="text-sm text-red-400">{error}</p>}

      <div className="flex items-center justify-between flex-wrap gap-3">
        <span className="text-xs text-white">
          {targets.length === 0
            ? 'No scan targets'
            : `Showing ${firstShown.toLocaleString()}–${lastShown.toLocaleString()} of ${targets.length.toLocaleString()} target${targets.length !== 1 ? 's' : ''}`}
        </span>
        <div className="flex items-center gap-2">
          <label htmlFor="targets-per-page" className="text-xs text-gray-400">Targets per page:</label>
          <select id="targets-per-page" value={pageSize}
            onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
            className="text-sm bg-gray-800 border border-gray-700 text-white rounded-lg px-2 py-1 focus:outline-none focus:border-sky-500">
            {PAGE_SIZE_OPTIONS.map(size => <option key={size} value={size}>{size}</option>)}
          </select>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Name</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Target</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Ports</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Schedule</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Last Scan</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Status</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {loading && <tr><td colSpan={7} className="px-4 py-8 text-center text-sm text-white">Loading…</td></tr>}
            {!loading && paged.map(t => (
              <tr key={t.id} className="hover:bg-gray-800/30 transition-colors">
                <td className="px-4 py-3 font-medium text-white">{t.name}</td>
                <td className="px-4 py-3 text-white font-mono text-xs">{t.host || t.cidr}</td>
                <td className="px-4 py-3 text-white text-xs">{t.ports}</td>
                <td className="px-4 py-3 text-white text-xs">{t.schedule_minutes === 0 ? 'Manual only' : `Every ${t.schedule_minutes}m`}</td>
                <td className="px-4 py-3 text-white text-xs">{t.last_scan_at ?? 'Never'}</td>
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${STATUS_STYLES[t.last_status]}`}>{t.last_status}</span>
                  {t.last_error && <p className="text-xs text-red-400 mt-0.5">{t.last_error}</p>}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-3">
                    <button onClick={() => handleScanNow(t)} disabled={scanningId === t.id} className="text-xs text-sky-400 hover:text-sky-300 disabled:opacity-50">
                      {scanningId === t.id ? 'Scanning…' : 'Scan Now'}
                    </button>
                    {isAdmin && (
                      <>
                        <button onClick={() => { setEditing(t); setAdding(false) }} className="text-xs text-white hover:text-sky-400 transition-colors">Edit</button>
                        <button onClick={() => handleDelete(t)} className="text-xs text-white hover:text-red-400 transition-colors">Delete</button>
                      </>
                    )}
                  </div>
                  {scanResult?.id === t.id && <p className="text-xs text-white mt-1">{scanResult.text}</p>}
                </td>
              </tr>
            ))}
            {!loading && targets.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-sm text-white">No scan targets yet — click "+ New target" to add one.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center">
          <Pagination page={pageClamped} totalPages={totalPages} onChange={setPage} />
        </div>
      )}
    </div>
  )
}
