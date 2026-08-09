import { useCallback, useEffect, useState } from 'react'
import { api, CertTemplate, CertificateAuthority } from '../api/client'
import { useAuth } from '../store/auth'
import HelpButton from '../components/HelpButton'
import ValidityInput, { formatValidity } from '../components/ValidityInput'

const KEY_USAGE_OPTIONS = ['digital_signature', 'key_encipherment', 'content_commitment', 'data_encipherment', 'key_agreement', 'key_cert_sign', 'crl_sign']
const EKU_OPTIONS = ['server_auth', 'client_auth', 'code_signing', 'email_protection', 'ocsp_signing', 'time_stamping']

interface FormData {
  name: string
  key_algorithm: string
  key_size: number
  validity_days: number
  key_usage: string[]
  extended_key_usage: string[]
  default_ca_id: number | ''
}

const EMPTY: FormData = {
  name: '', key_algorithm: 'rsa', key_size: 2048, validity_days: 365,
  key_usage: ['digital_signature', 'key_encipherment'], extended_key_usage: ['server_auth'], default_ca_id: '',
}

function fromTemplate(t: CertTemplate): FormData {
  return {
    name: t.name, key_algorithm: t.key_algorithm, key_size: t.key_size, validity_days: t.validity_days,
    key_usage: t.key_usage, extended_key_usage: t.extended_key_usage, default_ca_id: t.default_ca_id ?? '',
  }
}

function TemplateForm({ initial, cas, onSave, onCancel, saving }: {
  initial: FormData
  cas: CertificateAuthority[]
  onSave: (data: FormData) => Promise<void>
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState<FormData>(initial)
  const set = <K extends keyof FormData>(k: K, v: FormData[K]) => setForm(f => ({ ...f, [k]: v }))
  const inp = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500'

  const toggle = (key: 'key_usage' | 'extended_key_usage', value: string) => {
    set(key, form[key].includes(value) ? form[key].filter(v => v !== value) : [...form[key], value])
  }

  return (
    <div className="bg-gray-900 border border-sky-500/30 rounded-xl p-5 space-y-4">
      <h3 className="text-sm font-semibold text-white">{initial.name ? 'Edit template' : 'New template'}</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="sm:col-span-2">
          <label className="block text-xs text-white mb-1">Name</label>
          <input value={form.name} onChange={e => set('name', e.target.value)} placeholder="Standard TLS Server" className={inp} />
        </div>
        <div>
          <label className="block text-xs text-white mb-1">Key algorithm</label>
          <select value={form.key_algorithm} onChange={e => set('key_algorithm', e.target.value)} className={inp}>
            <option value="rsa">RSA</option>
            <option value="ec">EC</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-white mb-1">Key size</label>
          <select value={form.key_size} onChange={e => set('key_size', Number(e.target.value))} className={inp}>
            {form.key_algorithm === 'rsa' ? (
              <><option value={2048}>2048</option><option value={4096}>4096</option></>
            ) : (
              <><option value={2048}>P-256</option><option value={3072}>P-384</option><option value={4096}>P-521</option></>
            )}
          </select>
        </div>
        <div>
          <label className="block text-xs text-white mb-1">Validity</label>
          <ValidityInput days={form.validity_days} onChange={v => set('validity_days', v)} className={inp} />
        </div>
        <div>
          <label className="block text-xs text-white mb-1">Default CA</label>
          <select value={form.default_ca_id} onChange={e => set('default_ca_id', e.target.value ? Number(e.target.value) : '')} className={inp}>
            <option value="">None</option>
            {cas.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>
      </div>
      <div>
        <label className="block text-xs text-white mb-2">Key usage</label>
        <div className="flex flex-wrap gap-2">
          {KEY_USAGE_OPTIONS.map(v => (
            <button key={v} type="button" onClick={() => toggle('key_usage', v)}
              className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${form.key_usage.includes(v) ? 'bg-sky-600/30 border-sky-500 text-sky-300' : 'bg-gray-800 border-gray-700 text-white hover:border-gray-500'}`}>
              {v.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
      </div>
      <div>
        <label className="block text-xs text-white mb-2">Extended key usage</label>
        <div className="flex flex-wrap gap-2">
          {EKU_OPTIONS.map(v => (
            <button key={v} type="button" onClick={() => toggle('extended_key_usage', v)}
              className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${form.extended_key_usage.includes(v) ? 'bg-sky-600/30 border-sky-500 text-sky-300' : 'bg-gray-800 border-gray-700 text-white hover:border-gray-500'}`}>
              {v.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-3 pt-1">
        <button onClick={() => onSave(form)} disabled={saving || !form.name.trim()}
          className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
          {saving ? 'Saving…' : 'Save'}
        </button>
        <button onClick={onCancel} className="text-white hover:text-white text-sm border border-gray-700 rounded-lg px-4 py-2 transition-colors">Cancel</button>
      </div>
    </div>
  )
}

export default function Templates() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [templates, setTemplates] = useState<CertTemplate[]>([])
  const [cas, setCas] = useState<CertificateAuthority[]>([])
  const [loading, setLoading] = useState(true)
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<CertTemplate | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [t, c] = await Promise.all([api.getTemplates(), api.getCas()])
      setTemplates(t); setCas(c)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const caName = (id: number | null) => cas.find(c => c.id === id)?.name ?? '—'

  const handleSave = async (form: FormData) => {
    setSaving(true)
    setError('')
    try {
      const body = {
        name: form.name, key_algorithm: form.key_algorithm, key_size: form.key_size, validity_days: form.validity_days,
        key_usage: form.key_usage, extended_key_usage: form.extended_key_usage,
        default_ca_id: form.default_ca_id === '' ? null : Number(form.default_ca_id),
      }
      if (editing) {
        await api.updateTemplate(editing.id, body)
        setEditing(null)
      } else {
        await api.createTemplate(body)
        setAdding(false)
      }
      await load()
    } catch (e: any) {
      setError(e.message ?? 'Failed to save template')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (t: CertTemplate) => {
    if (!confirm(`Delete template "${t.name}"?`)) return
    await api.deleteTemplate(t.id)
    await load()
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-white">Templates</h1>
          <HelpButton title="Templates — How It Works">
            <p>Templates define what a newly issued certificate looks like: key algorithm/size, validity period, and the key usage / extended key usage extensions written into it. Pick one when issuing a certificate or signing a CSR.</p>
          </HelpButton>
        </div>
        {isAdmin && !adding && !editing && (
          <button onClick={() => setAdding(true)}
            className="bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors">
            + New template
          </button>
        )}
      </div>

      {adding && <TemplateForm initial={EMPTY} cas={cas} onSave={handleSave} onCancel={() => setAdding(false)} saving={saving} />}
      {editing && <TemplateForm initial={fromTemplate(editing)} cas={cas} onSave={handleSave} onCancel={() => setEditing(null)} saving={saving} />}
      {error && <p className="text-sm text-red-400">{error}</p>}

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Name</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Key</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Validity</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">EKU</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Default CA</th>
              {isAdmin && <th className="px-4 py-3"></th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {loading && <tr><td colSpan={isAdmin ? 6 : 5} className="px-4 py-8 text-center text-sm text-white">Loading…</td></tr>}
            {!loading && templates.map(t => (
              <tr key={t.id} className="hover:bg-gray-800/30 transition-colors">
                <td className="px-4 py-3 font-medium text-white">{t.name}</td>
                <td className="px-4 py-3 text-white text-xs">{t.key_algorithm.toUpperCase()} {t.key_size}</td>
                <td className="px-4 py-3 text-white">{formatValidity(t.validity_days)}</td>
                <td className="px-4 py-3 text-white text-xs">{t.extended_key_usage.join(', ')}</td>
                <td className="px-4 py-3 text-white text-xs">{caName(t.default_ca_id)}</td>
                {isAdmin && (
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <button onClick={() => { setEditing(t); setAdding(false) }} className="text-xs text-white hover:text-sky-400 transition-colors">Edit</button>
                      <button onClick={() => handleDelete(t)} className="text-xs text-white hover:text-red-400 transition-colors">Delete</button>
                    </div>
                  </td>
                )}
              </tr>
            ))}
            {!loading && templates.length === 0 && (
              <tr><td colSpan={isAdmin ? 6 : 5} className="px-4 py-8 text-center text-sm text-white">No templates yet — click "+ New template" to add one.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
