// Settings → Enrolment. Manages the credentials devices use to obtain their
// own certificates over EST or SCEP.
//
// A profile secret is a bearer credential: anything holding it can obtain a
// certificate. That's unavoidable for unattended device enrolment, so this
// screen is built around the two things that make it survivable — seeing what
// each profile is allowed to do, and being able to rotate or disable it in one
// click. The secret is shown exactly once, at creation.

import { useCallback, useEffect, useState } from 'react'
import { api, CertificateAuthority, CertTemplate, EnrollmentProfile, EnrollmentLogEntry } from '../api/client'
import HelpButton from '../components/HelpButton'

const INPUT = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500'

function fmtDate(ts: string | null): string {
  if (!ts) return '—'
  const utc = ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z'
  return new Date(utc).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function copyToClipboard(text: string) {
  navigator.clipboard?.writeText(text).catch(() => {})
}

function SecretBanner({ secret, onDismiss }: { secret: string; onDismiss: () => void }) {
  return (
    <div className="bg-amber-900/20 border border-amber-800/40 rounded-xl p-4 space-y-2">
      <p className="text-sm text-amber-300">
        This is the only time this secret is shown. Copy it into the device configuration now — pktCert stores it
        encrypted and cannot display it again. If you lose it, rotate the profile rather than recreating it.
      </p>
      <div className="flex items-center gap-3 flex-wrap">
        <code className="text-xs font-mono text-white bg-gray-800 border border-gray-700 rounded px-3 py-2 break-all">{secret}</code>
        <button onClick={() => copyToClipboard(secret)} className="text-xs text-sky-400 hover:text-sky-300">Copy</button>
        <button onClick={onDismiss} className="text-xs text-white hover:text-white border border-gray-700 rounded-lg px-3 py-1.5">Done</button>
      </div>
    </div>
  )
}

export default function Enrollment() {
  const [profiles, setProfiles] = useState<EnrollmentProfile[]>([])
  const [cas, setCas] = useState<CertificateAuthority[]>([])
  const [templates, setTemplates] = useState<CertTemplate[]>([])
  const [log, setLog] = useState<EnrollmentLogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [secret, setSecret] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // New-profile form
  const [name, setName] = useState('')
  const [protocol, setProtocol] = useState<'est' | 'scep'>('est')
  const [caId, setCaId] = useState<number | ''>('')
  const [templateId, setTemplateId] = useState<number | ''>('')
  const [username, setUsername] = useState('')
  const [suffix, setSuffix] = useState('')
  const [maxCerts, setMaxCerts] = useState('')
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [p, c, t, l] = await Promise.all([
        api.getEnrollmentProfiles(), api.getCas(), api.getTemplates(), api.getEnrollmentLog({ limit: 25 }),
      ])
      setProfiles(p)
      setCas(c)
      setTemplates(t)
      setLog(l)
      if (caId === '' && c.length) setCaId(c[0].id)
      if (templateId === '' && t.length) setTemplateId(t[0].id)
    } finally {
      setLoading(false)
    }
  }, [caId, templateId])

  useEffect(() => { load() }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  const create = async () => {
    setSaving(true); setError(null)
    try {
      const r = await api.createEnrollmentProfile({
        name, protocol, ca_id: Number(caId), template_id: Number(templateId),
        username, allowed_name_suffix: suffix,
        max_certs: maxCerts === '' ? null : Number(maxCerts),
      })
      setSecret(r.secret)
      setShowAdd(false)
      setName(''); setUsername(''); setSuffix(''); setMaxCerts('')
      await load()
    } catch (e: any) {
      setError(e.message ?? 'Could not create the profile')
    } finally { setSaving(false) }
  }

  const rotate = async (p: EnrollmentProfile) => {
    if (!confirm(`Rotate the secret for "${p.name}"?\n\nEvery device still using the old secret stops enrolling immediately.`)) return
    try {
      const r = await api.rotateEnrollmentSecret(p.id)
      setSecret(r.secret)
      await load()
    } catch (e: any) { setError(e.message ?? 'Could not rotate the secret') }
  }

  const toggle = async (p: EnrollmentProfile) => {
    try {
      await api.updateEnrollmentProfile(p.id, {
        name: p.name, protocol: p.protocol, ca_id: p.ca_id, template_id: p.template_id,
        username: p.username ?? '', allowed_name_suffix: p.allowed_name_suffix ?? '',
        max_certs: p.max_certs, enabled: !p.enabled,
      })
      await load()
    } catch (e: any) { setError(e.message ?? 'Could not update the profile') }
  }

  const remove = async (p: EnrollmentProfile) => {
    if (!confirm(`Delete enrolment profile "${p.name}"? Devices using it stop enrolling immediately.`)) return
    try {
      await api.deleteEnrollmentProfile(p.id)
      await load()
    } catch (e: any) { setError(e.message ?? 'Could not delete the profile') }
  }

  const caName = (id: number) => cas.find(c => c.id === id)?.name ?? `CA #${id}`
  const templateName = (id: number) => templates.find(t => t.id === id)?.name ?? `Template #${id}`

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <h2 className="text-lg font-semibold text-white">Enrolment</h2>
          <HelpButton title="Enrolment — How It Works">
            <p>Devices that support <span className="text-gray-300 font-medium">EST</span> (RFC 7030) can request their own certificates instead of someone issuing one by hand and copying files onto the box. The device generates its own key — pktCert never sees it — and sends only a certificate request.</p>
            <p>An <span className="text-gray-300 font-medium">enrolment profile</span> is what authorises that: a shared secret bound to one CA and one template. Anything holding the secret can obtain a certificate, so keep each profile as narrow as the job needs. The <span className="text-gray-300 font-medium">name suffix</span> restricts what names it may request — a profile for the switch fleet has no business issuing a certificate for the payroll server — and the <span className="text-gray-300 font-medium">certificate limit</span> caps the damage if the secret leaks.</p>
            <p>The secret is shown once, when the profile is created, and stored encrypted afterwards. Rotate it if it leaks; every device on the old secret stops enrolling immediately.</p>
            <p><span className="text-gray-300 font-medium">EST</span> devices go to <code className="text-gray-300">https://this-server/.well-known/est/</code> and authenticate with the profile's username and secret. <code className="text-gray-300">/cacerts</code> needs no credentials, so a device can install the trust anchor before it has anything to authenticate with.</p>
            <p><span className="text-gray-300 font-medium">SCEP</span> devices go to <code className="text-gray-300">http://this-server/scep</code> and use the profile's secret as their <em>challenge password</em>. There's no username. SCEP is the older protocol but it's what most network hardware and MDM actually speaks — Cisco, Juniper, Palo Alto, Fortinet, Intune. Its request body is encrypted to the CA, so unlike EST it doesn't require TLS.</p>
            <p><span className="text-gray-300 font-medium">EST requires TLS.</span> The request carries a secret that yields a trusted certificate, so over plain HTTP that secret belongs to anyone on the path. Enrolment over HTTP is refused unless you deliberately allow it for an isolated network.</p>
          </HelpButton>
        </div>
        <button onClick={() => setShowAdd(v => !v)}
          className="bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors">
          {showAdd ? 'Cancel' : '+ New Profile'}
        </button>
      </div>

      {secret && <SecretBanner secret={secret} onDismiss={() => setSecret(null)} />}
      {error && <div className="bg-red-900/20 border border-red-800/40 rounded-xl p-3 text-sm text-red-400">{error}</div>}

      {showAdd && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-white mb-1">Name</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="Access switch fleet" className={INPUT} />
            </div>
            <div>
              <label className="block text-xs text-white mb-1">Protocol</label>
              <select value={protocol} onChange={e => setProtocol(e.target.value as 'est' | 'scep')} className={INPUT}>
                <option value="est">EST (RFC 7030)</option>
                <option value="scep">SCEP (RFC 8894)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-white mb-1">Issuing CA</label>
              <select value={caId} onChange={e => setCaId(Number(e.target.value))} className={INPUT}>
                {cas.length === 0 && <option value="">No CAs available</option>}
                {cas.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-white mb-1">Template</label>
              <select value={templateId} onChange={e => setTemplateId(Number(e.target.value))} className={INPUT}>
                {templates.length === 0 && <option value="">No templates available</option>}
                {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-white mb-1">
                Username{protocol === 'scep' ? ' (not used by SCEP)' : ''}
              </label>
              <input value={username} onChange={e => setUsername(e.target.value)} placeholder="switches"
                disabled={protocol === 'scep'} className={INPUT} />
              <p className="text-xs text-slate-400 mt-1">
                {protocol === 'scep'
                  ? 'SCEP has no username — a device authenticates with the challenge password alone.'
                  : 'Devices authenticate with HTTP Basic — this is the username half.'}
              </p>
            </div>
            <div>
              <label className="block text-xs text-white mb-1">Allowed name suffix (optional)</label>
              <input value={suffix} onChange={e => setSuffix(e.target.value)} placeholder=".corp.example.com" className={INPUT} />
              <p className="text-xs text-slate-400 mt-1">Refuses any request for a name outside this suffix.</p>
            </div>
            <div>
              <label className="block text-xs text-white mb-1">Certificate limit (optional)</label>
              <input value={maxCerts} onChange={e => setMaxCerts(e.target.value)} type="number" min={1} placeholder="unlimited" className={INPUT} />
              <p className="text-xs text-slate-400 mt-1">Caps how many certificates this profile may ever issue.</p>
            </div>
          </div>
          <button onClick={create} disabled={saving || !name.trim() || !caId || !templateId || (protocol === 'est' && !username.trim())}
            className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
            {saving ? 'Creating…' : 'Create Profile'}
          </button>
        </div>
      )}

      {loading && <p className="text-sm text-white">Loading…</p>}

      {!loading && profiles.length === 0 && !showAdd && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center text-sm text-white">
          No enrolment profiles yet. Create one to let devices request their own certificates.
        </div>
      )}

      {profiles.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="f-tbl-cards w-full text-sm">
            <thead className="bg-gray-800/50">
              <tr className="text-left text-xs text-white">
                <th className="px-4 py-3">Profile</th>
                <th className="px-4 py-3">Issues</th>
                <th className="px-4 py-3">Restricted to</th>
                <th className="px-4 py-3">Used</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {profiles.map(p => (
                <tr key={p.id}>
                  <td data-label="Profile" className="px-4 py-3">
                    <div className="text-white">{p.name}</div>
                    <div className="text-xs text-white/70">
                      {p.protocol.toUpperCase()}
                      {p.username ? ` · ${p.username}` : ''}
                      {!p.enabled && <span className="text-amber-300"> · disabled</span>}
                    </div>
                  </td>
                  <td data-label="Issues" className="px-4 py-3 text-xs text-white">
                    {caName(p.ca_id)}<br /><span className="text-white/70">{templateName(p.template_id)}</span>
                  </td>
                  <td data-label="Restricted to" className="px-4 py-3 text-xs text-white">
                    {p.allowed_name_suffix || <span className="text-amber-300">any name</span>}
                    {p.max_certs !== null && <div className="text-white/70">{p.issued_count}/{p.max_certs} issued</div>}
                    {p.max_certs === null && <div className="text-white/70">{p.issued_count} issued</div>}
                  </td>
                  <td data-label="Used" className="px-4 py-3 text-xs text-white">{fmtDate(p.last_used_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3 justify-end">
                      <button onClick={() => rotate(p)} className="text-xs text-sky-400 hover:text-sky-300">Rotate secret</button>
                      <button onClick={() => toggle(p)} className="text-xs text-white hover:text-amber-300">
                        {p.enabled ? 'Disable' : 'Enable'}
                      </button>
                      <button onClick={() => remove(p)} className="text-xs text-white hover:text-red-400">Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {log.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-white mb-2">Recent enrolment attempts</h3>
          <div className="f-tbl-scroll bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full text-xs">
              <tbody className="divide-y divide-gray-800">
                {log.map(e => (
                  <tr key={e.id}>
                    <td className="px-4 py-2 text-white whitespace-nowrap">{fmtDate(e.created_at)}</td>
                    <td className="px-4 py-2 text-white">{e.protocol.toUpperCase()} {e.operation}</td>
                    <td className="px-4 py-2 text-white/70 font-mono">{e.client_ip}</td>
                    <td className="px-4 py-2 text-white/70 truncate max-w-xs">{e.subject ?? '—'}</td>
                    <td className="px-4 py-2">
                      <span className={
                        e.outcome === 'issued' ? 'text-emerald-400'
                          : e.outcome === 'denied' ? 'text-amber-300' : 'text-red-400'
                      }>{e.outcome}</span>
                      {e.detail && <span className="text-white/70"> — {e.detail}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
