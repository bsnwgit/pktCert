// Offline-root workflow dialogs.
//
// The root's private key never enters pktCert, so creating an intermediate
// takes three moves: generate a key + CSR here, sign that CSR on the machine
// holding the root key, bring the signed certificate back. These are the
// three dialogs for those steps, plus publishing a CRL that was likewise
// signed elsewhere — an offline CA cannot sign its own, which is the point
// rather than a gap.

import { useEffect, useState } from 'react'
import { api, CertificateAuthority } from '../api/client'
import { downloadFile, safeFilename } from '../utils/download'

const INPUT = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500'
const TEXTAREA = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white resize-none focus:outline-none focus:ring-2 focus:ring-sky-500'

function copyToClipboard(text: string) {
  navigator.clipboard?.writeText(text).catch(() => {})
}

function Shell({ children, onClose }: { children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 py-8 px-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 max-w-lg w-full max-h-[85vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}>
        {children}
      </div>
    </div>
  )
}

export function RequestIntermediateModal({ parent, onClose, onSaved }: {
  parent: CertificateAuthority; onClose: () => void; onSaved: () => void
}) {
  const [name, setName] = useState('')
  const [keyAlgorithm, setKeyAlgorithm] = useState('rsa')
  const [keySize, setKeySize] = useState(4096)
  const [pathLength, setPathLength] = useState('0')
  const [csr, setCsr] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const submit = async () => {
    setSaving(true); setError('')
    try {
      const r = await api.requestIntermediate({
        name, parent_ca_id: parent.id, key_algorithm: keyAlgorithm, key_size: keySize,
        path_length: pathLength === '' ? null : Number(pathLength),
      })
      setCsr(r.csr_pem)
      onSaved()
    } catch (e: any) {
      setError(e.message ?? 'Could not generate the CSR')
    } finally { setSaving(false) }
  }

  return (
    <Shell onClose={onClose}>
      {!csr ? (
        <>
          <h3 className="text-lg font-semibold text-white mb-1">Request Intermediate</h3>
          <p className="text-xs text-white mb-4">To be signed by <span className="text-sky-300">{parent.name}</span></p>
          <div className="space-y-4">
            <div>
              <label className="block text-xs text-white mb-1">Name</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="Issuing Intermediate CA" className={INPUT} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-white mb-1">Key algorithm</label>
                <select value={keyAlgorithm} onChange={e => setKeyAlgorithm(e.target.value)} className={INPUT}>
                  <option value="rsa">RSA</option>
                  <option value="ec">EC</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-white mb-1">Key size</label>
                <select value={keySize} onChange={e => setKeySize(Number(e.target.value))} className={INPUT}>
                  {keyAlgorithm === 'rsa' ? (
                    <><option value={2048}>2048</option><option value={4096}>4096</option></>
                  ) : (
                    <><option value={2048}>P-256</option><option value={3072}>P-384</option><option value={4096}>P-521</option></>
                  )}
                </select>
              </div>
            </div>
            <div>
              <label className="block text-xs text-white mb-1">Path length</label>
              <input value={pathLength} onChange={e => setPathLength(e.target.value)} type="number" min={0} max={5} className={INPUT} />
              <p className="text-xs text-slate-400 mt-1">
                0 means this CA can issue certificates but cannot create another CA beneath it.
              </p>
            </div>
            <p className="text-xs text-amber-300/90">
              The private key is generated here and never leaves. Only the CSR travels to the offline machine.
            </p>
            {error && <p className="text-sm text-red-400">{error}</p>}
            <div className="flex items-center gap-3 pt-1">
              <button onClick={submit} disabled={saving || !name.trim()}
                className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
                {saving ? 'Generating…' : 'Generate CSR'}
              </button>
              <button onClick={onClose} className="text-white text-sm border border-gray-700 rounded-lg px-4 py-2 transition-colors">Cancel</button>
            </div>
          </div>
        </>
      ) : (
        <>
          <h3 className="text-lg font-semibold text-white mb-2">Certificate Signing Request</h3>
          <p className="text-xs text-white mb-3">
            Take this to the machine holding <span className="text-sky-300">{parent.name}</span>&apos;s private key,
            sign it there, then use <span className="text-gray-300">Import Signed Certificate</span> on the new CA.
            The CSR can be re-downloaded later — it belongs to a key that already exists here, so regenerating it
            would produce a different one.
          </p>
          <div className="flex items-center gap-3 mb-2">
            <button onClick={() => copyToClipboard(csr)} className="text-xs text-sky-400 hover:text-sky-300">Copy</button>
            <button onClick={() => downloadFile(`${safeFilename(name)}.csr`, csr)} className="text-xs text-sky-400 hover:text-sky-300">Download</button>
          </div>
          <textarea readOnly value={csr} rows={12} className={TEXTAREA} />
          <button onClick={onClose}
            className="w-full mt-4 px-4 py-2 text-sm border border-gray-700 hover:border-gray-500 text-white rounded-lg transition-colors">
            Close
          </button>
        </>
      )}
    </Shell>
  )
}

export function SignedCertModal({ ca, onClose, onSaved }: {
  ca: CertificateAuthority; onClose: () => void; onSaved: () => void
}) {
  const [csr, setCsr] = useState('')
  const [certPem, setCertPem] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    api.getCaCsr(ca.id).then(r => setCsr(r.csr_pem)).catch(() => setCsr(''))
  }, [ca.id])

  const submit = async () => {
    setSaving(true); setError('')
    try {
      await api.importSignedCert(ca.id, certPem)
      onSaved()
      onClose()
    } catch (e: any) {
      setError(e.message ?? 'Could not import the signed certificate')
    } finally { setSaving(false) }
  }

  return (
    <Shell onClose={onClose}>
      <h3 className="text-lg font-semibold text-white mb-1">{ca.name}</h3>
      <p className="text-xs text-white mb-4">Awaiting its signed certificate</p>

      {csr && (
        <div className="mb-4">
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs text-white">CSR to sign</label>
            <div className="flex gap-3">
              <button onClick={() => copyToClipboard(csr)} className="text-xs text-sky-400 hover:text-sky-300">Copy</button>
              <button onClick={() => downloadFile(`${safeFilename(ca.name)}.csr`, csr)} className="text-xs text-sky-400 hover:text-sky-300">Download</button>
            </div>
          </div>
          <textarea readOnly value={csr} rows={6} className={TEXTAREA} />
        </div>
      )}

      <label className="block text-xs text-white mb-1">Signed certificate (PEM)</label>
      <textarea value={certPem} onChange={e => setCertPem(e.target.value)} rows={7}
        placeholder="-----BEGIN CERTIFICATE-----" className={TEXTAREA} />
      <p className="text-xs text-slate-400 mt-1">
        Checked before anything is stored: it must match the private key held here, be a CA certificate, and carry
        a signature that actually verifies against the parent.
      </p>
      {error && <p className="text-sm text-red-400 mt-2">{error}</p>}
      <div className="flex items-center gap-3 mt-4">
        <button onClick={submit} disabled={saving || !certPem.trim()}
          className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
          {saving ? 'Importing…' : 'Import & Activate'}
        </button>
        <button onClick={onClose} className="text-white text-sm border border-gray-700 rounded-lg px-4 py-2 transition-colors">Cancel</button>
      </div>
    </Shell>
  )
}

export function UploadCrlModal({ ca, onClose, onSaved }: {
  ca: CertificateAuthority; onClose: () => void; onSaved: () => void
}) {
  const [crlPem, setCrlPem] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<string | null>(null)

  const submit = async () => {
    setSaving(true); setError('')
    try {
      const r = await api.uploadCrl(ca.id, crlPem)
      setResult(`Published — ${r.revoked_count} revoked entr${r.revoked_count === 1 ? 'y' : 'ies'}, next update ${r.next_update ?? 'not set'}`)
      onSaved()
    } catch (e: any) {
      setError(e.message ?? 'Could not upload the CRL')
    } finally { setSaving(false) }
  }

  return (
    <Shell onClose={onClose}>
      <h3 className="text-lg font-semibold text-white mb-1">Publish CRL — {ca.name}</h3>
      <p className="text-xs text-white mb-4">
        This CA is offline, so pktCert holds no key to sign its CRL. Sign the CRL on the machine that holds the key
        and paste it here; it is then served at this CA&apos;s usual distribution point, exactly like any other.
      </p>
      <textarea value={crlPem} onChange={e => setCrlPem(e.target.value)} rows={9}
        placeholder="-----BEGIN X509 CRL-----" className={TEXTAREA} />
      {error && <p className="text-sm text-red-400 mt-2">{error}</p>}
      {result && <p className="text-sm text-emerald-400 mt-2">{result}</p>}
      <div className="flex items-center gap-3 mt-4">
        <button onClick={submit} disabled={saving || !crlPem.trim()}
          className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
          {saving ? 'Publishing…' : 'Publish'}
        </button>
        <button onClick={onClose} className="text-white text-sm border border-gray-700 rounded-lg px-4 py-2 transition-colors">Close</button>
      </div>
    </Shell>
  )
}
