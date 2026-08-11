import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, AlertRule, AlertEvent, AlertCondition, AlertConditionType } from '../api/client'
import { useAuth } from '../store/auth'
import TimeRangeControl, { TimeRange } from '../components/TimeRangeControl'
import Pagination from '../components/Pagination'
import HelpButton from '../components/HelpButton'

// Conditions and their parameters come from GET /api/alerts/conditions, so a
// condition added to the backend registry is configurable here immediately
// with no change to this file. This map is only a display fallback for a rule
// referencing something the server no longer offers.
const CONDITION_LABEL: Record<string, string> = {
  cert_expiring: 'Certificate expiring',
  cert_expired: 'Certificate expired',
  cert_revoked: 'Certificate revoked',
  ca_expiring: 'CA expiring',
  scan_target_unreachable: 'Scan target unreachable',
}

const CHANNELS_AVAILABLE = ['inapp', 'email', 'slack', 'pagerduty', 'webhook', 'tracecat']
const PAGE_SIZE_OPTIONS = [25, 50, 75, 100]

const SEV_STYLES: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/40',
  warning: 'bg-amber-500/20 text-amber-400 border border-amber-500/40',
  info: 'bg-sky-500/20 text-sky-400 border border-sky-500/40',
}

function fmtTime(ts: string): string {
  const utc = ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z'
  return new Date(utc).toLocaleString([], {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

// ── Event card ──────────────────────────────────────────────────────────────

function EventCard({ event, onAck, onResolve }: { event: AlertEvent; onAck: () => void; onResolve: () => void }) {
  const isAcked = event.acked
  const isResolved = event.resolved && !isAcked

  return (
    <div className={`bg-gray-900 border rounded-xl p-4 transition-opacity ${
      isAcked ? 'opacity-40 border-gray-800' : isResolved ? 'opacity-70 border-gray-700' : 'border-gray-700'
    }`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3 min-w-0">
          <span className={`shrink-0 text-xs px-2 py-0.5 rounded-full font-medium capitalize ${SEV_STYLES[event.severity] ?? SEV_STYLES.info}`}>
            {event.severity}
          </span>
          {event.auto_resolved && (
            <span className="shrink-0 text-xs px-2 py-0.5 rounded-full font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
              auto-resolved
            </span>
          )}
          <div className="min-w-0">
            <p className="text-sm text-white">{event.message}</p>
            {isResolved && event.resolved_at && (
              <p className="text-xs text-emerald-500/70 mt-0.5">Resolved {fmtTime(event.resolved_at)}</p>
            )}
          </div>
        </div>
        <div className="shrink-0 flex items-center gap-2">
          <span className="text-xs text-white">{fmtTime(event.created_at)}</span>
          {event.active && (
            <button onClick={onResolve}
              className="text-xs bg-gray-800 hover:bg-gray-700 text-white border border-gray-700 rounded px-2.5 py-1 transition-colors">
              Resolve
            </button>
          )}
          {!isAcked && (
            <button onClick={onAck}
              className="text-xs bg-gray-800 hover:bg-gray-700 text-white border border-gray-700 rounded px-2.5 py-1 transition-colors">
              Ack
            </button>
          )}
          {isAcked && <span className="text-xs text-emerald-500">✓ Acked</span>}
        </div>
      </div>
    </div>
  )
}

// ── Rule form (inline, not modal) ─────────────────────────────────────────────

interface RuleFormData {
  name: string
  condition_type: AlertConditionType
  threshold: number
  severity: 'info' | 'warning' | 'critical'
  cooldown_min: string
  channels: string[]
  params: Record<string, unknown>
  scope: Record<string, unknown>
}

function fromRule(r: AlertRule): RuleFormData {
  return {
    name: r.name, condition_type: r.condition_type, threshold: r.threshold ?? 85,
    severity: r.severity, cooldown_min: String(r.cooldown_min), channels: r.channels,
    params: r.params ?? {}, scope: r.scope ?? {},
  }
}

const EMPTY_RULE: RuleFormData = {
  name: '', condition_type: 'cert_expiring', threshold: 30,
  severity: 'warning', cooldown_min: '15', channels: ['inapp'],
  params: {}, scope: {},
}

// One parameter input, rendered from what the condition says it accepts.
function ParamField({ param, value, onChange }: {
  param: AlertCondition['params'][number]
  value: unknown
  onChange: (v: unknown) => void
}) {
  const inp = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500'
  const current = value ?? param.default

  if (param.type === 'multiselect') {
    const selected = Array.isArray(current) ? (current as string[]) : []
    return (
      <div>
        <label className="block text-xs text-white mb-1">{param.label}</label>
        <div className="flex flex-wrap gap-2">
          {param.options.map(opt => {
            const on = selected.includes(opt)
            return (
              <button key={opt} type="button"
                onClick={() => onChange(on ? selected.filter(o => o !== opt) : [...selected, opt])}
                className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
                  on ? 'bg-sky-600/30 border-sky-500 text-sky-300' : 'bg-gray-800 border-gray-700 text-white hover:border-gray-500'
                }`}>
                {opt}
              </button>
            )
          })}
        </div>
        {param.hint && <p className="text-xs text-slate-400 mt-1">{param.hint}</p>}
      </div>
    )
  }

  return (
    <div>
      <label className="block text-xs text-white mb-1">{param.label}</label>
      <input
        type={param.type === 'int' ? 'number' : 'text'}
        min={param.min ?? undefined} max={param.max ?? undefined}
        value={String(current ?? '')}
        onChange={e => onChange(param.type === 'int' ? Number(e.target.value) : e.target.value)}
        className={inp} />
      {param.hint && <p className="text-xs text-slate-400 mt-1">{param.hint}</p>}
    </div>
  )
}

function RuleForm({ initial, conditions, onSave, onCancel, saving }: {
  initial: RuleFormData
  conditions: AlertCondition[]
  onSave: (data: RuleFormData) => Promise<void>
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState<RuleFormData>(initial)
  const condition = conditions.find(c => c.key === form.condition_type)
  const setParam = (key: string, v: unknown) => setForm(f => ({ ...f, params: { ...f.params, [key]: v } }))
  const setScope = (key: string, v: unknown) => setForm(f => {
    const scope = { ...f.scope }
    if (v === '' || v === null) delete scope[key]
    else scope[key] = v
    return { ...f, scope }
  })
  const set = <K extends keyof RuleFormData>(k: K, v: RuleFormData[K]) => setForm(f => ({ ...f, [k]: v }))

  const toggleChannel = (ch: string) => {
    set('channels', form.channels.includes(ch) ? form.channels.filter(c => c !== ch) : [...form.channels, ch])
  }

  const inp = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500'

  return (
    <div className="bg-gray-900 border border-sky-500/30 rounded-xl p-5 space-y-5">
      <h3 className="text-sm font-semibold text-white">{initial.name ? 'Edit rule' : 'New alert rule'}</h3>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="sm:col-span-2">
          <label className="block text-xs text-white mb-1">Rule name</label>
          <input value={form.name} onChange={e => set('name', e.target.value)} placeholder="My alert rule" className={inp} />
        </div>
        <div className="sm:col-span-2">
          <label className="block text-xs text-white mb-1">Condition</label>
          <select value={form.condition_type}
            onChange={e => setForm(f => ({ ...f, condition_type: e.target.value as AlertConditionType, params: {} }))}
            className={inp}>
            {conditions.length === 0 && <option value={form.condition_type}>{CONDITION_LABEL[form.condition_type] ?? form.condition_type}</option>}
            {conditions.map(c => <option key={c.key} value={c.key}>{c.label}</option>)}
          </select>
          {condition && <p className="text-xs text-slate-400 mt-1">{condition.description}</p>}
        </div>
        <div>
          <label className="block text-xs text-white mb-1">Severity</label>
          <select value={form.severity} onChange={e => set('severity', e.target.value as 'info' | 'warning' | 'critical')} className={inp}>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-white mb-1">Cooldown (minutes)</label>
          <input type="number" min={0} max={1440} value={form.cooldown_min} onChange={e => set('cooldown_min', e.target.value)} className={inp} />
        </div>
      </div>

      {condition && condition.params.length > 0 && (
        <div className="border-t border-gray-800 pt-4">
          <label className="block text-xs text-white mb-2">Condition settings</label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {condition.params.map(pm => (
              <ParamField key={pm.key} param={pm} value={form.params[pm.key]}
                onChange={v => setParam(pm.key, v)} />
            ))}
          </div>
        </div>
      )}

      {condition?.scoped && (
        <div className="border-t border-gray-800 pt-4">
          <label className="block text-xs text-white mb-2">Limit to (optional)</label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-white mb-1">Source</label>
              <select value={String(form.scope.source ?? '')} onChange={e => setScope('source', e.target.value)} className={inp}>
                <option value="">Any source</option>
                <option value="issued">Issued by pktCert</option>
                <option value="enrolled">Enrolled by a device</option>
                <option value="scan">Found by scanning</option>
                <option value="ct">Found in CT logs</option>
                <option value="external">Uploaded</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-white mb-1">Name contains</label>
              <input value={String(form.scope.name_like ?? '')} onChange={e => setScope('name_like', e.target.value)}
                placeholder="e.g. .corp.example.com" className={inp} />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs text-white mb-1">Host contains</label>
              <input value={String(form.scope.host_like ?? '')} onChange={e => setScope('host_like', e.target.value)}
                placeholder="e.g. 10.20." className={inp} />
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Leave blank to watch everything. Narrow rules are the ones that get acted on — a rule covering the
            whole inventory is noise on day one and ignored by day three.
          </p>
        </div>
      )}

      <div>
        <label className="block text-xs text-white mb-2">Notification channels</label>
        <div className="flex flex-wrap gap-2">
          {CHANNELS_AVAILABLE.map(ch => {
            const active = form.channels.includes(ch)
            return (
              <button key={ch} type="button" onClick={() => toggleChannel(ch)}
                className={`text-xs px-3 py-1.5 rounded-lg border transition-colors capitalize ${
                  active ? 'bg-sky-600/30 border-sky-500 text-sky-300' : 'bg-gray-800 border-gray-700 text-white hover:border-gray-500'
                }`}>
                {ch}
              </button>
            )
          })}
        </div>
      </div>

      <div className="flex items-center gap-3 pt-1">
        <button onClick={() => onSave(form)} disabled={saving || !form.name.trim()}
          className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
          {saving ? 'Saving…' : 'Save rule'}
        </button>
        <button onClick={onCancel} className="text-white hover:text-white text-sm border border-gray-700 rounded-lg px-4 py-2 transition-colors">
          Cancel
        </button>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

type Tab = 'active' | 'history' | 'rules'

export default function Alerts() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [tab, setTab] = useState<Tab>('active')
  const [events, setEvents] = useState<AlertEvent[]>([])
  const [history, setHistory] = useState<AlertEvent[]>([])
  const [rules, setRules] = useState<AlertRule[]>([])
  const [conditions, setConditions] = useState<AlertCondition[]>([])
  const [loading, setLoading] = useState(true)
  const [addingRule, setAddingRule] = useState(false)
  const [editRule, setEditRule] = useState<AlertRule | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const [eventsFilter, setEventsFilter] = useState('')
  const [eventsSevFilter, setEventsSevFilter] = useState('')
  const [eventsWindow, setEventsWindow] = useState<TimeRange>({ since: null, until: null })
  const [eventsPage, setEventsPage] = useState(1)
  const [eventsPageSize, setEventsPageSize] = useState(25)

  const [historyFilter, setHistoryFilter] = useState('')
  const [historySevFilter, setHistorySevFilter] = useState('')
  const [historyWindow, setHistoryWindow] = useState<TimeRange>({ since: null, until: null })
  const [historyPage, setHistoryPage] = useState(1)
  const [historyPageSize, setHistoryPageSize] = useState(25)

  const [rulesFilter, setRulesFilter] = useState('')
  const [ackingAll, setAckingAll] = useState(false)
  const [rulesExporting, setRulesExporting] = useState(false)
  const [importResult, setImportResult] = useState<{ created: number; skipped: number; errors: string[] } | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const loadEvents = useCallback(async () => {
    setLoading(true)
    try {
      const [ev, hist] = await Promise.all([
        api.getAlertEvents({ acked: false, since: eventsWindow.since, until: eventsWindow.until, limit: 500 }),
        api.getAlertEvents({ acked: true, since: historyWindow.since, until: historyWindow.until, limit: 500 }),
      ])
      setEvents(ev)
      setHistory(hist)
    } finally {
      setLoading(false)
    }
  }, [eventsWindow, historyWindow])

  const loadRules = useCallback(async () => {
    setRules(await api.getAlertRules())
    // The condition registry drives the rule form's fields, so it has to
    // be loaded before a rule can be sensibly edited.
    try { setConditions(await api.getAlertConditions()) } catch { /* older backend */ }
  }, [])

  useEffect(() => { loadEvents() }, [loadEvents])
  useEffect(() => { loadRules() }, [loadRules])

  const filteredEvents = useMemo(() => events.filter(e =>
    (!eventsSevFilter || e.severity === eventsSevFilter) &&
    (!eventsFilter || e.message.toLowerCase().includes(eventsFilter.toLowerCase()))
  ), [events, eventsSevFilter, eventsFilter])
  const eventsTotalPages = Math.max(1, Math.ceil(filteredEvents.length / eventsPageSize))
  const eventsPageClamped = Math.min(eventsPage, eventsTotalPages)
  const pagedEvents = filteredEvents.slice((eventsPageClamped - 1) * eventsPageSize, eventsPageClamped * eventsPageSize)

  const changeEventsPageSize = (size: number) => {
    setEventsPageSize(size)
    setEventsPage(1)
  }

  const filteredHistory = useMemo(() => history.filter(e =>
    (!historySevFilter || e.severity === historySevFilter) &&
    (!historyFilter || e.message.toLowerCase().includes(historyFilter.toLowerCase()))
  ), [history, historySevFilter, historyFilter])
  const historyTotalPages = Math.max(1, Math.ceil(filteredHistory.length / historyPageSize))
  const historyPageClamped = Math.min(historyPage, historyTotalPages)
  const pagedHistory = filteredHistory.slice((historyPageClamped - 1) * historyPageSize, historyPageClamped * historyPageSize)

  const changeHistoryPageSize = (size: number) => {
    setHistoryPageSize(size)
    setHistoryPage(1)
  }

  const filteredRules = useMemo(() => rules.filter(r => {
    if (!rulesFilter) return true
    const q = rulesFilter.toLowerCase()
    return r.name.toLowerCase().includes(q) || r.condition_type.toLowerCase().includes(q) || r.severity.toLowerCase().includes(q)
  }), [rules, rulesFilter])

  const ack = async (e: AlertEvent) => { await api.ackAlertEvent(e.id); await loadEvents() }
  const resolve = async (e: AlertEvent) => { await api.resolveAlertEvent(e.id); await loadEvents() }

  const ackAll = async () => {
    setAckingAll(true)
    try { await api.ackAllAlertEvents(); await loadEvents() } finally { setAckingAll(false) }
  }

  const handleToggleRule = async (rule: AlertRule) => {
    setRules(rs => rs.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r))
    try {
      await api.toggleAlertRule(rule.id)
    } catch {
      setRules(rs => rs.map(r => r.id === rule.id ? { ...r, enabled: rule.enabled } : r))
    }
  }

  const handleDeleteRule = async (rule: AlertRule) => {
    if (!confirm(`Delete alert rule "${rule.name}"?`)) return
    await api.deleteAlertRule(rule.id)
    await loadRules()
  }

  const handleSaveRule = async (form: RuleFormData) => {
    setSaving(true)
    setError('')
    try {
      const body = {
        name: form.name, condition_type: form.condition_type,
        // threshold is retained only for rules created before parameters
        // existed; new rules carry their days value in params.
        threshold: null,
        severity: form.severity, enabled: true,
        cooldown_min: parseInt(form.cooldown_min) || 15,
        channels: form.channels,
        params: form.params, scope: form.scope,
      }
      if (editRule) {
        await api.updateAlertRule(editRule.id, body)
        setEditRule(null)
      } else {
        await api.createAlertRule(body)
        setAddingRule(false)
      }
      await loadRules()
    } catch (e: any) {
      setError(e.message ?? 'Failed to save rule')
    } finally {
      setSaving(false)
    }
  }

  const handleDownloadTemplate = () => {
    const rows = [
      ['name', 'condition_type', 'threshold', 'severity', 'enabled', 'cooldown_min', 'channels'],
      ['Certs expiring in 30 days', 'cert_expiring', '30', 'warning', 'true', '15', 'inapp,email'],
    ]
    const csv = rows.map(r => r.map(v => `"${v.replace(/"/g, '""')}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'pktcert-alert-rules-template.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  const exportCsv = async () => {
    setRulesExporting(true)
    try {
      const blob = await api.exportAlertRules()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = 'pktcert-alert-rules.csv'; a.click()
      URL.revokeObjectURL(url)
    } catch (e: any) {
      setError(e.message ?? 'Export failed')
    } finally {
      setRulesExporting(false)
    }
  }

  const importCsv = async (file: File) => {
    setImportResult(null)
    try {
      const result = await api.importAlertRulesCsv(file)
      setImportResult(result)
      if (result.created > 0) await loadRules()
    } catch (e: any) {
      setImportResult({ created: 0, skipped: 0, errors: [e.message ?? 'Import failed'] })
    }
  }

  const unackedCount = events.length

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white">Alerts</h1>
            <HelpButton title="Alerts — How It Works">
              <p>Rules watch certificate and CA expiration windows, revocations, and scan targets stuck in an error state — each rule fires an event when its condition is met, and auto-resolves once it clears (revocation is terminal and never auto-resolves).</p>
              <p>A rule watches for one <span className="text-gray-300 font-medium">condition</span> — expiry, a key that's too short, a SHA-1 signature, a self-signed certificate, an issuer you don't control, a CRL about to lapse, and more. Each condition has its own settings, so you decide what "too short" or "too soon" means here rather than living with a number someone else picked.</p><p><span className="text-gray-300 font-medium">Limit to</span> narrows a rule to part of the inventory — one source, a name or host pattern. Narrow rules are the ones that get acted on; a rule covering everything is noise on day one and ignored by day three.</p><p>Events notify on whichever channels a rule has enabled — in-app, email, Slack, PagerDuty, webhook, or TraceCat. Every channel except in-app must first be configured and enabled under Settings → Notifications; a rule targeting an unconfigured channel is skipped rather than failed. Only the tick that opens an event notifies, so a certificate that stays expiring won't re-notify every minute.</p>
              <p>Import Rules CSV lets you bulk-create rules instead of adding them one at a time.</p>
            </HelpButton>
          </div>
          <p className="text-sm text-white mt-0.5">
            {(() => {
              const active = events.filter(e => e.active).length
              const resolved = events.filter(e => !e.active).length
              if (active > 0) return `${active} active alert${active !== 1 ? 's' : ''}${resolved > 0 ? `, ${resolved} auto-resolved` : ''}`
              if (resolved > 0) return `${resolved} auto-resolved alert${resolved !== 1 ? 's' : ''} — all conditions cleared`
              return 'No active alerts'
            })()}
          </p>
        </div>
        {tab === 'active' && events.length > 0 && (
          <button onClick={ackAll} disabled={ackingAll}
            className="text-sm border border-gray-700 hover:border-gray-500 text-white rounded-lg px-4 py-2 transition-colors disabled:opacity-50">
            {ackingAll ? 'Acking…' : 'Ack all'}
          </button>
        )}
        {tab === 'rules' && isAdmin && !addingRule && !editRule && (
          <div className="flex items-center gap-2">
            <button onClick={exportCsv} disabled={rulesExporting}
              className="px-3 py-2 text-sm bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50">
              {rulesExporting ? 'Exporting…' : '↓ Export CSV'}
            </button>
            <div className="flex items-center gap-1">
              <button onClick={() => fileInputRef.current?.click()}
                className="px-3 py-2 text-sm bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors rounded-r-none border-r border-gray-600">
                ↑ Import CSV
              </button>
              <button onClick={handleDownloadTemplate} title="Download CSV template"
                className="px-2 py-2 text-sm bg-gray-700 hover:bg-gray-600 text-white hover:text-white rounded-lg transition-colors rounded-l-none">
                template
              </button>
            </div>
            <input ref={fileInputRef} type="file" accept=".csv" className="hidden"
              onChange={e => { const f = e.target.files?.[0]; if (f) importCsv(f); e.target.value = '' }} />
            <button onClick={() => setAddingRule(true)}
              className="bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors">
              + New rule
            </button>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900 border border-gray-800 rounded-xl p-1 w-fit">
        {(['active', 'history', 'rules'] as Tab[]).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`text-sm px-4 py-1.5 rounded-lg transition-colors capitalize ${tab === t ? 'bg-gray-700 text-white' : 'text-white hover:text-white'}`}>
            {t}
            {t === 'active' && unackedCount > 0 && (
              <span className="ml-1.5 bg-red-500 text-white text-xs rounded-full px-1.5 py-0.5">{unackedCount}</span>
            )}
          </button>
        ))}
      </div>

      {/* Active events */}
      {tab === 'active' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <input value={eventsFilter} onChange={e => { setEventsFilter(e.target.value); setEventsPage(1) }}
              placeholder="Filter by message…"
              className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white placeholder-gray-600 w-56 focus:outline-none focus:ring-1 focus:ring-sky-500" />
            {eventsFilter && <button onClick={() => { setEventsFilter(''); setEventsPage(1) }} className="text-xs text-white hover:text-white">✕</button>}
            <select value={eventsSevFilter} onChange={e => { setEventsSevFilter(e.target.value); setEventsPage(1) }}
              className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white focus:outline-none focus:ring-1 focus:ring-sky-500">
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
            </select>
            {eventsSevFilter && <button onClick={() => { setEventsSevFilter(''); setEventsPage(1) }} className="text-xs text-white hover:text-white">✕</button>}
            <TimeRangeControl value={eventsWindow} onChange={w => { setEventsWindow(w); setEventsPage(1) }} />
            {(eventsFilter || eventsSevFilter) && (
              <span className="text-xs text-white ml-auto">{filteredEvents.length} result{filteredEvents.length !== 1 ? 's' : ''}</span>
            )}
          </div>
          {loading && <p className="text-sm text-white">Loading…</p>}
          {!loading && events.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-white">
              <p className="text-2xl mb-2">✓</p>
              <p className="text-sm">No unacknowledged alerts</p>
            </div>
          )}
          {!loading && events.length > 0 && filteredEvents.length === 0 && (
            <p className="text-sm text-white text-center py-8">No alerts match this filter</p>
          )}
          {filteredEvents.length > 0 && (
            <div className="flex items-center justify-center gap-6">
              <Pagination page={eventsPageClamped} totalPages={eventsTotalPages} onChange={setEventsPage} />
              <div className="flex items-center gap-2">
                <label htmlFor="active-alerts-per-page" className="text-xs text-gray-400">Alerts per page:</label>
                <select
                  id="active-alerts-per-page"
                  value={eventsPageSize}
                  onChange={e => changeEventsPageSize(Number(e.target.value))}
                  className="text-sm bg-gray-800 border border-gray-700 text-white rounded-lg px-2 py-1 focus:outline-none focus:border-sky-500"
                >
                  {PAGE_SIZE_OPTIONS.map(size => (
                    <option key={size} value={size}>{size}</option>
                  ))}
                </select>
              </div>
            </div>
          )}
          <div className="space-y-2">
            {pagedEvents.map(e => <EventCard key={e.id} event={e} onAck={() => ack(e)} onResolve={() => resolve(e)} />)}
          </div>
          {filteredEvents.length > 0 && (
            <p className="text-xs text-white pt-1">
              Showing {((eventsPageClamped - 1) * eventsPageSize + 1).toLocaleString()}–{((eventsPageClamped - 1) * eventsPageSize + pagedEvents.length).toLocaleString()} of {filteredEvents.length.toLocaleString()} alerts
            </p>
          )}
        </div>
      )}

      {/* History */}
      {tab === 'history' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <input value={historyFilter} onChange={e => { setHistoryFilter(e.target.value); setHistoryPage(1) }}
              placeholder="Filter by message…"
              className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white placeholder-gray-600 w-56 focus:outline-none focus:ring-1 focus:ring-sky-500" />
            {historyFilter && <button onClick={() => { setHistoryFilter(''); setHistoryPage(1) }} className="text-xs text-white hover:text-white">✕</button>}
            <select value={historySevFilter} onChange={e => { setHistorySevFilter(e.target.value); setHistoryPage(1) }}
              className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white focus:outline-none focus:ring-1 focus:ring-sky-500">
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
            </select>
            {historySevFilter && <button onClick={() => { setHistorySevFilter(''); setHistoryPage(1) }} className="text-xs text-white hover:text-white">✕</button>}
            <TimeRangeControl value={historyWindow} onChange={w => { setHistoryWindow(w); setHistoryPage(1) }} />
            {(historyFilter || historySevFilter) && (
              <span className="text-xs text-white ml-auto">{filteredHistory.length} result{filteredHistory.length !== 1 ? 's' : ''}</span>
            )}
          </div>
          {history.length === 0 && !loading && (
            <div className="flex flex-col items-center justify-center h-32 text-white">
              <p className="text-sm">No alert history</p>
            </div>
          )}
          {history.length > 0 && filteredHistory.length === 0 && (
            <p className="text-sm text-white text-center py-8">No alerts match this filter</p>
          )}
          {filteredHistory.length > 0 && (
            <div className="flex items-center justify-center gap-6">
              <Pagination page={historyPageClamped} totalPages={historyTotalPages} onChange={setHistoryPage} />
              <div className="flex items-center gap-2">
                <label htmlFor="history-alerts-per-page" className="text-xs text-gray-400">Alerts per page:</label>
                <select
                  id="history-alerts-per-page"
                  value={historyPageSize}
                  onChange={e => changeHistoryPageSize(Number(e.target.value))}
                  className="text-sm bg-gray-800 border border-gray-700 text-white rounded-lg px-2 py-1 focus:outline-none focus:border-sky-500"
                >
                  {PAGE_SIZE_OPTIONS.map(size => (
                    <option key={size} value={size}>{size}</option>
                  ))}
                </select>
              </div>
            </div>
          )}
          <div className="space-y-2">
            {pagedHistory.map(e => <EventCard key={e.id} event={e} onAck={() => ack(e)} onResolve={() => resolve(e)} />)}
          </div>
          {filteredHistory.length > 0 && (
            <p className="text-xs text-white pt-1">
              Showing {((historyPageClamped - 1) * historyPageSize + 1).toLocaleString()}–{((historyPageClamped - 1) * historyPageSize + pagedHistory.length).toLocaleString()} of {filteredHistory.length.toLocaleString()} alerts
            </p>
          )}
        </div>
      )}

      {/* Rules */}
      {tab === 'rules' && (
        <div className="space-y-4">
          {addingRule && <RuleForm initial={EMPTY_RULE} conditions={conditions} onSave={handleSaveRule} onCancel={() => setAddingRule(false)} saving={saving} />}
          {editRule && <RuleForm initial={fromRule(editRule)} conditions={conditions} onSave={handleSaveRule} onCancel={() => setEditRule(null)} saving={saving} />}
          {error && <p className="text-sm text-red-400">{error}</p>}

          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-4 py-2.5 border-b border-gray-800 flex items-center gap-3 flex-wrap">
              <input value={rulesFilter} onChange={e => setRulesFilter(e.target.value)} placeholder="Filter by name, condition, severity…"
                className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white placeholder-gray-600 w-64 focus:outline-none focus:ring-1 focus:ring-sky-500" />
              {rulesFilter && <button onClick={() => setRulesFilter('')} className="text-xs text-white hover:text-white">✕</button>}
              <span className="text-xs text-white ml-auto">{filteredRules.length} rule{filteredRules.length !== 1 ? 's' : ''}</span>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="px-4 py-3 text-left text-xs font-medium text-white">Enabled</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-white">Rule</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-white">Condition</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-white">Threshold</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-white">Severity</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-white">Channels</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-white">Cooldown</th>
                  {isAdmin && <th className="px-4 py-3"></th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {filteredRules.map(rule => (
                  <tr key={rule.id} className="hover:bg-gray-800/30 transition-colors">
                    <td className="px-4 py-3">
                      <button onClick={() => handleToggleRule(rule)} disabled={!isAdmin}
                        className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors disabled:opacity-50 ${rule.enabled ? 'bg-sky-600' : 'bg-gray-700'}`}>
                        <span className={`inline-block h-3 w-3 rounded-full bg-white transition-transform ${rule.enabled ? 'translate-x-5' : 'translate-x-1'}`} />
                      </button>
                    </td>
                    <td className="px-4 py-3 font-medium text-white">{rule.name}</td>
                    <td className="px-4 py-3 text-white text-xs">
                      {conditions.find(c => c.key === rule.condition_type)?.label
                        ?? CONDITION_LABEL[rule.condition_type] ?? rule.condition_type}
                    </td>
                    <td className="px-4 py-3 text-white">{rule.threshold ?? '—'}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${SEV_STYLES[rule.severity] ?? SEV_STYLES.info}`}>{rule.severity}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-white">{rule.channels.join(', ')}</td>
                    <td className="px-4 py-3 text-white">{rule.cooldown_min}m</td>
                    {isAdmin && (
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <button onClick={() => { setEditRule(rule); setAddingRule(false) }} className="text-xs text-white hover:text-sky-400 transition-colors">Edit</button>
                          <button onClick={() => handleDeleteRule(rule)} className="text-xs text-white hover:text-red-400 transition-colors">Delete</button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
                {filteredRules.length === 0 && (
                  <tr><td colSpan={isAdmin ? 8 : 7} className="px-4 py-8 text-center text-sm text-white">
                    {rulesFilter ? 'No rules match this filter' : 'No alert rules yet — click "+ New rule" to add one'}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {importResult && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 py-8 px-4" onClick={() => setImportResult(null)}>
          <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 max-w-lg w-full" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-semibold text-white mb-3">Import complete</h3>
            <div className="space-y-1 mb-4">
              <p className="text-sm text-emerald-400">✓ {importResult.created} rule{importResult.created !== 1 ? 's' : ''} created</p>
              {importResult.skipped > 0 && <p className="text-sm text-amber-400">⚠ {importResult.skipped} row{importResult.skipped !== 1 ? 's' : ''} skipped</p>}
            </div>
            {importResult.errors.length > 0 && (
              <div className="bg-gray-800 rounded-lg px-3 py-2 max-h-36 overflow-y-auto mb-4">
                {importResult.errors.map((e, i) => <p key={i} className="text-xs text-red-400 font-mono">{e}</p>)}
              </div>
            )}
            <div className="bg-gray-800/60 rounded-lg px-3 py-2 mb-4">
              <p className="text-xs font-medium text-white mb-1">CSV columns (header row required)</p>
              <p className="text-xs font-mono text-white break-all">name, condition_type, threshold, severity, enabled, cooldown_min, channels</p>
              <p className="text-xs text-white mt-1">channels: comma-separated (e.g. inapp,email).</p>
            </div>
            <div className="flex items-center justify-between">
              <button onClick={handleDownloadTemplate} className="text-xs text-sky-400 hover:text-sky-300 transition-colors">↓ Download template</button>
              <button onClick={() => setImportResult(null)} className="px-4 py-2 text-sm bg-sky-600 hover:bg-sky-500 text-white rounded-lg">Done</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
