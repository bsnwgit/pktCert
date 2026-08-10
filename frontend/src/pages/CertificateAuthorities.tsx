import { useCallback, useEffect, useState } from 'react'
import { api, CertificateAuthority } from '../api/client'
import { useAuth } from '../store/auth'
import HelpButton from '../components/HelpButton'
import ValidityInput from '../components/ValidityInput'
import { downloadFile, safeFilename } from '../utils/download'

const STATUS_STYLES: Record<string, string> = {
  active: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40',
  disabled: 'bg-slate-500/20 text-slate-300 border border-slate-500/40',
  expired: 'bg-red-500/20 text-red-400 border border-red-500/40',
  revoked: 'bg-gray-500/20 text-gray-400 border border-gray-500/40',
}

function fmtDate(ts: string): string {
  const utc = ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z'
  return new Date(utc).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
}

function copyToClipboard(text: string) {
  navigator.clipboard?.writeText(text).catch(() => {})
}

function GenerateModal({ cas, onClose, onSaved }: { cas: CertificateAuthority[]; onClose: () => void; onSaved: () => void }) {
  const [mode, setMode] = useState<'generate' | 'import'>('generate')
  const [name, setName] = useState('')
  const [caType, setCaType] = useState<'root' | 'intermediate'>('root')
  const [parentCaId, setParentCaId] = useState<number | ''>('')
  const [keyAlgorithm, setKeyAlgorithm] = useState('rsa')
  const [keySize, setKeySize] = useState(4096)
  const [validityDays, setValidityDays] = useState(3650)
  const [pathLength, setPathLength] = useState('')
  const [permittedDns, setPermittedDns] = useState('')
  const [excludedDns, setExcludedDns] = useState('')
  const [permittedIp, setPermittedIp] = useState('')
  const [excludedIp, setExcludedIp] = useState('')
  const [showConstraints, setShowConstraints] = useState(false)
  const [certPem, setCertPem] = useState('')
  const [privateKeyPem, setPrivateKeyPem] = useState('')
  const [importPassphrase, setImportPassphrase] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const rootCas = cas.filter(c => c.ca_type === 'root' && c.status === 'active')

  const submit = async () => {
    setSaving(true)
    setError('')
    try {
      if (mode === 'generate') {
        const list = (v: string) => v.split(',').map(x => x.trim()).filter(Boolean)
        await api.generateCa({
          name, ca_type: caType, parent_ca_id: caType === 'intermediate' ? Number(parentCaId) : null,
          key_algorithm: keyAlgorithm, key_size: keySize, validity_days: validityDays,
          path_length: pathLength === '' ? null : Number(pathLength),
          permitted_dns: list(permittedDns), excluded_dns: list(excludedDns),
          permitted_ip: list(permittedIp), excluded_ip: list(excludedIp),
        })
      } else {
        await api.importCa({
          name, cert_pem: certPem, private_key_pem: privateKeyPem, ca_type: caType,
          parent_ca_id: caType === 'intermediate' ? Number(parentCaId) : null,
          ...(importPassphrase ? { key_passphrase: importPassphrase } : {}),
        })
      }
      onSaved()
      onClose()
    } catch (e: any) {
      setError(e.message ?? 'Failed to save CA')
    } finally {
      setSaving(false)
    }
  }

  const inp = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500'

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 py-8 px-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 max-w-lg w-full max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-semibold text-white mb-4">Add Certificate Authority</h3>
        <div className="flex gap-1 bg-gray-800 border border-gray-700 rounded-xl p-1 w-fit mb-4">
          {(['generate', 'import'] as const).map(m => (
            <button key={m} onClick={() => setMode(m)}
              className={`text-sm px-4 py-1.5 rounded-lg transition-colors capitalize ${mode === m ? 'bg-gray-700 text-white' : 'text-white hover:text-white'}`}>
              {m}
            </button>
          ))}
        </div>
        <div className="space-y-4">
          <div>
            <label className="block text-xs text-white mb-1">Name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="pktCert Internal Root CA" className={inp} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-white mb-1">Type</label>
              <select value={caType} onChange={e => setCaType(e.target.value as 'root' | 'intermediate')} className={inp}>
                <option value="root">Root</option>
                <option value="intermediate">Intermediate</option>
              </select>
            </div>
            {caType === 'intermediate' && (
              <div>
                <label className="block text-xs text-white mb-1">Parent CA</label>
                <select value={parentCaId} onChange={e => setParentCaId(Number(e.target.value))} className={inp}>
                  <option value="">Select…</option>
                  {rootCas.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </div>
            )}
          </div>

          {mode === 'generate' ? (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-white mb-1">Key algorithm</label>
                <select value={keyAlgorithm} onChange={e => setKeyAlgorithm(e.target.value)} className={inp}>
                  <option value="rsa">RSA</option>
                  <option value="ec">EC</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-white mb-1">Key size</label>
                <select value={keySize} onChange={e => setKeySize(Number(e.target.value))} className={inp}>
                  {keyAlgorithm === 'rsa' ? (
                    <><option value={2048}>2048</option><option value={4096}>4096</option></>
                  ) : (
                    <><option value={2048}>P-256</option><option value={3072}>P-384</option><option value={4096}>P-521</option></>
                  )}
                </select>
              </div>
              <div className="col-span-2">
                <label className="block text-xs text-white mb-1">Validity</label>
                <ValidityInput days={validityDays} onChange={setValidityDays} className={inp} />
              </div>

              <div className="col-span-2 border-t border-gray-800 pt-3">
                <button type="button" onClick={() => setShowConstraints(v => !v)}
                  className="text-xs text-sky-400 hover:text-sky-300">
                  {showConstraints ? '▾' : '▸'} Constraints (optional, recommended)
                </button>
                {showConstraints && (
                  <div className="mt-3 space-y-3">
                    <div>
                      <label className="block text-xs text-white mb-1">Maximum CAs below this one (path length)</label>
                      <input value={pathLength} onChange={e => setPathLength(e.target.value)} type="number" min={0} max={5}
                        placeholder={caType === 'intermediate' ? '0 (default)' : 'unlimited (default)'} className={inp} />
                      <p className="text-xs text-slate-400 mt-1">
                        0 means this CA can issue certificates but cannot create another CA beneath it.
                        Intermediates default to 0.
                      </p>
                    </div>
                    <div>
                      <label className="block text-xs text-white mb-1">Permitted DNS domains (comma-separated)</label>
                      <input value={permittedDns} onChange={e => setPermittedDns(e.target.value)}
                        placeholder=".corp.example.com, .internal.example.com" className={inp} />
                    </div>
                    <div>
                      <label className="block text-xs text-white mb-1">Excluded DNS domains</label>
                      <input value={excludedDns} onChange={e => setExcludedDns(e.target.value)}
                        placeholder=".public.example.com" className={inp} />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs text-white mb-1">Permitted IP ranges</label>
                        <input value={permittedIp} onChange={e => setPermittedIp(e.target.value)}
                          placeholder="10.0.0.0/8" className={inp} />
                      </div>
                      <div>
                        <label className="block text-xs text-white mb-1">Excluded IP ranges</label>
                        <input value={excludedIp} onChange={e => setExcludedIp(e.target.value)}
                          placeholder="0.0.0.0/0" className={inp} />
                      </div>
                    </div>
                    <p className="text-xs text-amber-300/90">
                      Name constraints are the strongest containment available for an internal CA: one limited to
                      .corp.example.com cannot mint a working certificate for anything else, even if its private key
                      is stolen. They are baked into the CA certificate at creation and cannot be changed afterwards —
                      set them now or reissue the CA later.
                    </p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-white mb-1">Certificate (PEM)</label>
                <textarea value={certPem} onChange={e => setCertPem(e.target.value)} rows={5} placeholder="-----BEGIN CERTIFICATE-----"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white resize-none focus:outline-none focus:ring-2 focus:ring-sky-500" />
              </div>
              <div>
                <label className="block text-xs text-white mb-1">Private Key (PEM)</label>
                <textarea value={privateKeyPem} onChange={e => setPrivateKeyPem(e.target.value)} rows={5} placeholder="-----BEGIN PRIVATE KEY-----"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white resize-none focus:outline-none focus:ring-2 focus:ring-sky-500" />
              </div>
              <div>
                <label className="block text-xs text-white mb-1">Key passphrase (if the key is encrypted)</label>
                <input type="password" value={importPassphrase} onChange={e => setImportPassphrase(e.target.value)}
                  autoComplete="new-password" placeholder="Leave blank for an unencrypted key" className={inp} />
                <p className="text-xs text-slate-400 mt-1">
                  Needed for a key beginning <span className="font-mono">ENCRYPTED PRIVATE KEY</span>. pktCert
                  decrypts it once on import and stores it under its own encryption at rest — the passphrase
                  itself is not kept.
                </p>
              </div>
            </div>
          )}

          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex items-center gap-3 pt-1">
            <button onClick={submit} disabled={saving || !name.trim() || (caType === 'intermediate' && !parentCaId) || (mode === 'import' && (!certPem.trim() || !privateKeyPem.trim()))}
              className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
              {saving ? 'Saving…' : mode === 'generate' ? 'Generate' : 'Import'}
            </button>
            <button onClick={onClose} className="text-white hover:text-white text-sm border border-gray-700 rounded-lg px-4 py-2 transition-colors">Cancel</button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function CertificateAuthorities() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [cas, setCas] = useState<CertificateAuthority[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [crl, setCrl] = useState<
    { id: number; text: string; number: number; issued: string; expires: string } | null
  >(null)

  const load = useCallback(async () => {
    setLoading(true)
    try { setCas(await api.getCas()) } finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const handleToggleStatus = async (ca: CertificateAuthority) => {
    const next = ca.status === 'disabled' ? 'active' : 'disabled'
    if (next === 'disabled' && !confirm(
      `Disable CA "${ca.name}"?\n\n` +
      'It will stop issuing new certificates. Everything it has already issued keeps working, ' +
      'and its CRL keeps being published — so revocations still reach the clients that need them.'
    )) return
    try {
      await api.setCaStatus(ca.id, next)
      await load()
    } catch (e: any) {
      alert(e.message ?? 'Could not change CA status')
    }
  }

  const handleDelete = async (ca: CertificateAuthority) => {
    if (!confirm(`Delete CA "${ca.name}"? Only possible if it has never issued a certificate.`)) return
    try {
      await api.deleteCa(ca.id)
      await load()
    } catch (e: any) {
      alert(e.message ?? 'Failed to delete CA')
    }
  }

  const handleCrl = async (ca: CertificateAuthority) => {
    const r = await api.getCrl(ca.id)
    setCrl({ id: ca.id, text: r.crl_pem, number: r.crl_number, issued: r.this_update, expires: r.next_update })
  }

  const rootCas = cas.filter(c => c.ca_type === 'root')
  const childrenOf = (id: number) => cas.filter(c => c.parent_ca_id === id)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-white">Certificate Authorities</h1>
          <HelpButton title="Certificate Authorities — How It Works">
            <p>Generate a new root (self-signed) or intermediate (signed by a root you control) CA, or import an existing one. CA private keys are encrypted at rest and are never returned by the API — they're only used server-side to sign issued certificates and CRLs.</p>
            <p><b>Disable</b> a CA to retire it: it stops issuing, but everything it already issued keeps working and its CRL keeps being published, so revocations still reach the clients that need them. That's almost always what you want.</p><p><b>Delete</b> only works on a CA that has never issued anything. Deleting one that has would destroy the key that signs its CRL, leaving every certificate it issued unrevocable while they're still deployed and trusted.</p><p>Constraints — path length and name constraints — are set when a CA is created and cannot be changed afterwards. A name-constrained CA cannot issue a working certificate outside its permitted domains even if its key is stolen.</p>
          </HelpButton>
        </div>
        {isAdmin && (
          <button onClick={() => setShowAdd(true)}
            className="bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors">
            + Add CA
          </button>
        )}
      </div>

      {loading && <p className="text-sm text-white">Loading…</p>}
      {!loading && cas.length === 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center text-sm text-white">
          No Certificate Authorities yet — click "+ Add CA" to generate a root CA.
        </div>
      )}

      <div className="space-y-3">
        {rootCas.map(ca => (
          <div key={ca.id} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-5 py-3 flex items-center justify-between gap-3 cursor-pointer" onClick={() => setExpanded(expanded === ca.id ? null : ca.id)}>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-white truncate">{ca.name}</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${STATUS_STYLES[ca.status]}`}>{ca.status}</span>
                  <span className="text-xs text-white">root</span>
                </div>
                <p className="text-xs text-white mt-0.5">
                  Expires {fmtDate(ca.not_after)} · {ca.key_algorithm.toUpperCase()} {ca.key_size} · {childrenOf(ca.id).length} intermediate(s)
                  {ca.path_length !== null && <> · path len {ca.path_length}</>}
                  {ca.name_constraints && <span className="text-emerald-400"> · name-constrained</span>}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0" onClick={e => e.stopPropagation()}>
                <button onClick={() => copyToClipboard(ca.cert_pem)} className="text-xs text-sky-400 hover:text-sky-300">Copy Cert</button>
                <button onClick={() => downloadFile(`${safeFilename(ca.name)}.pem`, ca.cert_pem)} className="text-xs text-sky-400 hover:text-sky-300">Download Cert</button>
                <button onClick={() => handleCrl(ca)} className="text-xs text-sky-400 hover:text-sky-300">CRL</button>
                {isAdmin && (
                  <button onClick={() => handleToggleStatus(ca)} className="text-xs text-white hover:text-amber-300">
                    {ca.status === 'disabled' ? 'Enable' : 'Disable'}
                  </button>
                )}
                {isAdmin && <button onClick={() => handleDelete(ca)} className="text-xs text-white hover:text-red-400">Delete</button>}
              </div>
            </div>
            {expanded === ca.id && childrenOf(ca.id).length > 0 && (
              <div className="border-t border-gray-800 divide-y divide-gray-800/60">
                {childrenOf(ca.id).map(child => (
                  <div key={child.id} className="px-5 py-3 pl-10 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-white truncate">{child.name}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${STATUS_STYLES[child.status]}`}>{child.status}</span>
                        <span className="text-xs text-white">intermediate</span>
                      </div>
                      <p className="text-xs text-white mt-0.5">Expires {fmtDate(child.not_after)} · {child.key_algorithm.toUpperCase()} {child.key_size}</p>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <button onClick={() => copyToClipboard(child.cert_pem)} className="text-xs text-sky-400 hover:text-sky-300">Copy Cert</button>
                      <button onClick={() => downloadFile(`${safeFilename(child.name)}.pem`, child.cert_pem)} className="text-xs text-sky-400 hover:text-sky-300">Download Cert</button>
                      <button onClick={() => handleCrl(child)} className="text-xs text-sky-400 hover:text-sky-300">CRL</button>
                      {isAdmin && (
                        <button onClick={() => handleToggleStatus(child)} className="text-xs text-white hover:text-amber-300">
                          {child.status === 'disabled' ? 'Enable' : 'Disable'}
                        </button>
                      )}
                      {isAdmin && <button onClick={() => handleDelete(child)} className="text-xs text-white hover:text-red-400">Delete</button>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {crl && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 py-8 px-4" onClick={() => setCrl(null)}>
          <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 max-w-lg w-full" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-lg font-semibold text-white">Certificate Revocation List</h3>
              <button onClick={() => copyToClipboard(crl.text)} className="text-xs text-sky-400 hover:text-sky-300">Copy</button>
            </div>
            {/* The CRL number and validity window are encoded inside the PEM
                below, where nobody can read them. Surface them here — the
                number is how a relying party tells one published CRL from
                another, and "Valid until" is when clients start rejecting
                this copy as stale. */}
            <div className="flex flex-wrap gap-x-5 gap-y-1 mb-3 text-xs text-white">
              <span>CRL Number <span className="font-mono text-sky-300">{crl.number}</span></span>
              <span>Issued <span className="text-sky-300">{fmtDate(crl.issued)}</span></span>
              <span>Valid until <span className="text-sky-300">{fmtDate(crl.expires)}</span></span>
            </div>
            <textarea readOnly value={crl.text} rows={10} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white resize-none" />
            <button onClick={() => setCrl(null)} className="w-full mt-4 px-4 py-2 text-sm border border-gray-700 hover:border-gray-500 text-white rounded-lg transition-colors">Close</button>
          </div>
        </div>
      )}

      {showAdd && <GenerateModal cas={cas} onClose={() => setShowAdd(false)} onSaved={load} />}
    </div>
  )
}
