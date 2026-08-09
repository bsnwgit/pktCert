import { useState } from 'react'

export interface TimeRange {
  since: string | null   // "YYYY-MM-DD HH:MM:SS" UTC, matching SQLite's datetime('now') format — or null for open-ended
  until: string | null
}

type Preset = '1h' | '6h' | '24h' | '7d' | '30d' | 'all' | 'custom'

const PRESETS: Array<{ id: Preset; label: string; hours?: number }> = [
  { id: '1h', label: 'Last hour', hours: 1 },
  { id: '6h', label: 'Last 6 hours', hours: 6 },
  { id: '24h', label: 'Last 24 hours', hours: 24 },
  { id: '7d', label: 'Last 7 days', hours: 24 * 7 },
  { id: '30d', label: 'Last 30 days', hours: 24 * 30 },
  { id: 'all', label: 'All time' },
  { id: 'custom', label: 'Custom range…' },
]

function toSqlUtc(d: Date): string {
  return d.toISOString().slice(0, 19).replace('T', ' ')
}

// datetime-local inputs give "YYYY-MM-DDTHH:MM" in the browser's local
// time zone — this converts that to the same UTC SQL-text format everything
// else in the app stores timestamps as.
function localInputToSqlUtc(local: string): string | null {
  if (!local) return null
  const d = new Date(local)
  if (isNaN(d.getTime())) return null
  return toSqlUtc(d)
}

function sqlUtcToLocalInput(sql: string | null): string {
  if (!sql) return ''
  const d = new Date(sql.replace(' ', 'T') + 'Z')
  if (isNaN(d.getTime())) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export default function TimeRangeControl({ value, onChange }: { value: TimeRange; onChange: (v: TimeRange) => void }) {
  const [preset, setPreset] = useState<Preset>('all')
  const [customFrom, setCustomFrom] = useState('')
  const [customTo, setCustomTo] = useState('')
  const [error, setError] = useState('')

  const nowLocal = (() => {
    const d = new Date()
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
  })()

  const selectPreset = (p: Preset) => {
    setPreset(p)
    setError('')
    if (p === 'custom') {
      setCustomFrom(sqlUtcToLocalInput(value.since))
      setCustomTo(sqlUtcToLocalInput(value.until))
      return
    }
    const meta = PRESETS.find(x => x.id === p)
    if (p === 'all' || !meta?.hours) {
      onChange({ since: null, until: null })
      return
    }
    const since = new Date(Date.now() - meta.hours * 3600_000)
    onChange({ since: toSqlUtc(since), until: null })
  }

  const applyCustom = (from: string, to: string) => {
    setCustomFrom(from)
    setCustomTo(to)
    if (from && to && new Date(from) > new Date(to)) {
      setError('"From" must be before "To"')
      return
    }
    setError('')
    onChange({ since: localInputToSqlUtc(from), until: localInputToSqlUtc(to) })
  }

  const selectCls = 'bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-sky-500'
  const inputCls = 'bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-sky-500'

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <select value={preset} onChange={e => selectPreset(e.target.value as Preset)} className={selectCls}>
        {PRESETS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
      </select>
      {preset === 'custom' && (
        <>
          <input type="datetime-local" value={customFrom} max={nowLocal}
            onChange={e => applyCustom(e.target.value, customTo)} className={inputCls} />
          <span className="text-xs text-white">to</span>
          <input type="datetime-local" value={customTo} max={nowLocal}
            onChange={e => applyCustom(customFrom, e.target.value)} className={inputCls} />
        </>
      )}
      {error && <span className="text-xs text-red-400">{error}</span>}
    </div>
  )
}
