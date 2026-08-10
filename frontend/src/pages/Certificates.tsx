import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, Certificate, CertificateAuthority, CertTemplate } from '../api/client'
import { useAuth } from '../store/auth'
import HelpButton from '../components/HelpButton'
import Pagination from '../components/Pagination'
import ConfirmPasswordModal from '../components/ConfirmPasswordModal'
import { downloadFile, safeFilename } from '../utils/download'

type PendingAction = { title: string; description: string; run: (password: string) => Promise<void> }

const STATUS_STYLES: Record<string, string> = {
  valid: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40',
  expiring: 'bg-amber-500/20 text-amber-400 border border-amber-500/40',
  expired: 'bg-red-500/20 text-red-400 border border-red-500/40',
  revoked: 'bg-gray-500/20 text-gray-400 border border-gray-500/40',
  superseded: 'bg-slate-500/20 text-slate-300 border border-slate-500/40',
  unknown: 'bg-sky-500/20 text-sky-400 border border-sky-500/40',
}

// RFC 5280 §5.3.1 reasonCode values, published in the CRL entry. Ordered by
// how often they're actually the right answer, not by their numeric code.
const REVOCATION_REASONS: { value: string; label: string }[] = [
  { value: 'unspecified', label: 'Unspecified' },
  { value: 'superseded', label: 'Superseded — replaced by another certificate' },
  { value: 'cessation_of_operation', label: 'Cessation of operation — service retired' },
  { value: 'key_compromise', label: 'Key compromise — the private key was exposed' },
  { value: 'affiliation_changed', label: 'Affiliation changed — subject details no longer correct' },
  { value: 'privilege_withdrawn', label: 'Privilege withdrawn — no longer authorised' },
  { value: 'ca_compromise', label: 'CA compromise — the issuing CA key was exposed' },
  { value: 'certificate_hold', label: 'Certificate hold — temporarily suspended' },
  { value: 'aa_compromise', label: 'AA compromise — attribute authority exposed' },
]

const PAGE_SIZE = 25

function fmtDate(ts: string | null): string {
  if (!ts) return '—'
  const utc = ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z'
  return new Date(utc).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
}

function copyToClipboard(text: string) {
  navigator.clipboard?.writeText(text).catch(() => {})
}

// ── Issue Certificate modal ────────────────────────────────────────────────

function IssueModal({ cas, templates, onClose, onIssued }: {
  cas: CertificateAuthority[]
  templates: CertTemplate[]
  onClose: () => void
  onIssued: () => void
}) {
  const [commonName, setCommonName] = useState('')
  const [sans, setSans] = useState('')
  const [caId, setCaId] = useState<number | ''>(cas[0]?.id ?? '')
  const [templateId, setTemplateId] = useState<number | ''>(templates[0]?.id ?? '')
  const [protectKey, setProtectKey] = useState(false)
  const [keyPassphrase, setKeyPassphrase] = useState('')
  const [keyPassphrase2, setKeyPassphrase2] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [issued, setIssued] = useState<Certificate | null>(null)
  const [pending, setPending] = useState<PendingAction | null>(null)

  const submit = async () => {
    if (!commonName.trim() || !caId || !templateId) return
    if (protectKey) {
      if (!keyPassphrase) { setError('Enter a key passphrase, or turn off key protection.'); return }
      if (keyPassphrase !== keyPassphrase2) { setError('Key passphrases do not match.'); return }
    }
    setSaving(true)
    setError('')
    try {
      const sanList = sans.split(',').map(s => s.trim()).filter(Boolean)
      const cert = await api.issueCertificate({
        common_name: commonName.trim(), sans: sanList, ca_id: Number(caId), template_id: Number(templateId),
        ...(protectKey && keyPassphrase ? { key_passphrase: keyPassphrase } : {}),
      })
      setIssued(cert)
      onIssued()
    } catch (e: any) {
      setError(e.message ?? 'Failed to issue certificate')
    } finally {
      setSaving(false)
    }
  }

  const inp = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500'

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 py-8 px-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 max-w-lg w-full max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        {!issued ? (
          <>
            <h3 className="text-lg font-semibold text-white mb-4">Issue Certificate</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-white mb-1">Common Name</label>
                <input value={commonName} onChange={e => setCommonName(e.target.value)} placeholder="server.internal.example.com" className={inp} />
              </div>
              <div>
                <label className="block text-xs text-white mb-1">Subject Alternative Names (comma-separated)</label>
                <input value={sans} onChange={e => setSans(e.target.value)} placeholder="alt1.example.com, 10.0.0.5" className={inp} />
                <p className="text-xs text-slate-400 mt-1">Common Name is added automatically — browsers ignore CN for hostname matching, so list every other hostname/IP the cert must be valid for here.</p>
              </div>
              <div>
                <label className="block text-xs text-white mb-1">Certificate Authority</label>
                <select value={caId} onChange={e => setCaId(Number(e.target.value))} className={inp}>
                  {cas.length === 0 && <option value="">No CAs available — create one first</option>}
                  {cas.map(ca => <option key={ca.id} value={ca.id}>{ca.name} ({ca.ca_type})</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-white mb-1">Template</label>
                <select value={templateId} onChange={e => setTemplateId(Number(e.target.value))} className={inp}>
                  {templates.length === 0 && <option value="">No templates available</option>}
                  {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                </select>
              </div>
              <div className="border-t border-gray-800 pt-3">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked={protectKey} onChange={e => setProtectKey(e.target.checked)}
                    className="rounded border-gray-600 bg-gray-800 text-sky-500 focus:ring-sky-500" />
                  <span className="text-sm text-white">Protect the private key with a passphrase (optional)</span>
                </label>
                {protectKey && (
                  <div className="mt-3 space-y-3">
                    <div>
                      <label className="block text-xs text-white mb-1">Key passphrase</label>
                      <input type="password" value={keyPassphrase} onChange={e => setKeyPassphrase(e.target.value)}
                        autoComplete="new-password" placeholder="Required to install the key on a remote server" className={inp} />
                    </div>
                    <div>
                      <label className="block text-xs text-white mb-1">Confirm passphrase</label>
                      <input type="password" value={keyPassphrase2} onChange={e => setKeyPassphrase2(e.target.value)}
                        autoComplete="new-password" placeholder="Re-enter passphrase" className={inp} />
                    </div>
                    <p className="text-xs text-amber-300/90">
                      The exported private key will be encrypted with this passphrase. pktCert does not store it —
                      whoever installs the key must enter it, and it cannot be recovered if lost.
                    </p>
                  </div>
                )}
              </div>
              {error && <p className="text-sm text-red-400">{error}</p>}
              <div className="flex items-center gap-3 pt-1">
                <button onClick={submit} disabled={saving || !commonName.trim() || !caId || !templateId}
                  className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
                  {saving ? 'Issuing…' : 'Issue'}
                </button>
                <button onClick={onClose} className="text-white hover:text-white text-sm border border-gray-700 rounded-lg px-4 py-2 transition-colors">Cancel</button>
              </div>
            </div>
          </>
        ) : (
          <>
            <h3 className="text-lg font-semibold text-emerald-400 mb-3">Certificate issued</h3>
            <p className="text-sm text-white mb-3">Copy the private key now — it won't be shown in plain text again after you close this dialog.</p>
            {issued.key_encrypted && (
              <p className="text-xs text-amber-300 mb-3 bg-amber-950/40 border border-amber-800/60 rounded-lg px-3 py-2">
                🔒 This private key is passphrase-protected. Keep the passphrase you set — it's required to install
                the key on a remote server and is not stored by pktCert.
              </p>
            )}
            {issued.private_key_pem && (
              <div className="mb-4">
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs text-white">Private Key (PEM){issued.key_encrypted ? ' — encrypted' : ''}</label>
                  <div className="flex gap-3">
                    <button onClick={() => copyToClipboard(issued.private_key_pem!)} className="text-xs text-sky-400 hover:text-sky-300">Copy</button>
                    <button onClick={() => downloadFile(`${safeFilename(issued.common_name)}-key.pem`, issued.private_key_pem!)} className="text-xs text-sky-400 hover:text-sky-300">Download</button>
                  </div>
                </div>
                <textarea readOnly value={issued.private_key_pem} rows={6}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white resize-none" />
              </div>
            )}
            <div className="mb-4">
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs text-white">Certificate (PEM)</label>
                <div className="flex gap-3">
                  <button onClick={() => setPending({
                    title: 'Confirm your password',
                    description: 'Re-enter your current password to copy the certificate PEM. This access is logged.',
                    run: async password => { const r = await api.downloadCertificate(issued.id, 'pem', password); copyToClipboard(r.pem) },
                  })} className="text-xs text-sky-400 hover:text-sky-300">Copy</button>
                  <button onClick={() => setPending({
                    title: 'Confirm your password',
                    description: 'Re-enter your current password to download the certificate PEM. This access is logged.',
                    run: async password => { const r = await api.downloadCertificate(issued.id, 'pem', password); downloadFile(`${safeFilename(issued.common_name)}.pem`, r.pem) },
                  })} className="text-xs text-sky-400 hover:text-sky-300">Download</button>
                </div>
              </div>
            </div>
            <button onClick={onClose} className="w-full px-4 py-2 text-sm bg-sky-600 hover:bg-sky-500 text-white rounded-lg">Done</button>
          </>
        )}
      </div>
      {pending && <ConfirmPasswordModal title={pending.title} description={pending.description} onConfirm={pending.run} onClose={() => setPending(null)} />}
    </div>
  )
}

// ── Detail / download modal ────────────────────────────────────────────────
// Every certificate/chain/key/passcode access here — viewing or downloading
// to a file — is a fresh step-up re-auth via ConfirmPasswordModal: the
// caller re-enters their current password every single time (no caching
// across actions), and each is audit-logged server-side (cert_events).

function DetailModal({ cert, isAdmin, onClose, onChanged }: { cert: Certificate; isAdmin: boolean; onClose: () => void; onChanged: () => void }) {
  const [pem, setPem] = useState<{ fmt: string; text: string } | null>(null)
  const [pending, setPending] = useState<PendingAction | null>(null)
  const [revoking, setRevoking] = useState(false)
  const [reason, setReason] = useState('')
  const [reasonCode, setReasonCode] = useState('unspecified')
  const [renewing, setRenewing] = useState(false)
  const [renewedKey, setRenewedKey] = useState<{ id: number; pem?: string } | null>(null)
  const [autoRenew, setAutoRenew] = useState(cert.auto_renew)
  const [autoRenewDays, setAutoRenewDays] = useState(String(cert.auto_renew_days))

  // Only certificates this pktCert issued can be renewed — renewal reuses the
  // original CA and template, neither of which exists for a discovered or
  // externally-issued cert.
  const renewable = cert.source === 'issued' && cert.ca_id !== null && cert.template_id !== null

  const filenameBase = safeFilename(cert.common_name)

  const viewPem = (fmt: 'pem' | 'chain') => setPending({
    title: 'Confirm your password',
    description: `Re-enter your current password to view the ${fmt === 'chain' ? 'chain' : 'certificate'} PEM. This access is logged.`,
    run: async password => { const r = await api.downloadCertificate(cert.id, fmt, password); setPem({ fmt, text: r.pem }) },
  })

  const downloadPem = (fmt: 'pem' | 'chain') => setPending({
    title: 'Confirm your password',
    description: `Re-enter your current password to download the ${fmt === 'chain' ? 'chain' : 'certificate'} PEM. This access is logged.`,
    run: async password => {
      const r = await api.downloadCertificate(cert.id, fmt, password)
      downloadFile(`${filenameBase}${fmt === 'chain' ? '-chain' : ''}.pem`, r.pem)
    },
  })

  const revealSecret = (field: 'key' | 'passcode') => setPending({
    title: 'Confirm your password',
    description: `Re-enter your current password to reveal the ${field === 'key' ? 'private key' : 'install passcode'}. This access is logged.`,
    run: async password => {
      const res = await api.revealCertificateSecret(cert.id, field, password)
      setPem({ fmt: field === 'key' ? 'private key' : 'passcode', text: (field === 'key' ? res.key : res.passcode) ?? '' })
    },
  })

  const downloadSecret = (field: 'key' | 'passcode') => setPending({
    title: 'Confirm your password',
    description: `Re-enter your current password to download the ${field === 'key' ? 'private key' : 'install passcode'}. This access is logged.`,
    run: async password => {
      const res = await api.revealCertificateSecret(cert.id, field, password)
      const value = (field === 'key' ? res.key : res.passcode) ?? ''
      downloadFile(field === 'key' ? `${filenameBase}-key.pem` : `${filenameBase}-passcode.txt`, value, field === 'key' ? 'application/x-pem-file' : 'text/plain')
    },
  })

  const doRenew = async () => {
    if (!confirm(
      `Renew '${cert.common_name}'?\n\n` +
      'A new certificate and a new private key will be issued from the same CA and template. ' +
      'The current certificate stays valid and is marked superseded — it is NOT revoked, so ' +
      'the running service keeps working until you install the replacement.'
    )) return
    setRenewing(true)
    try {
      const res = await api.renewCertificate(cert.id)
      setRenewedKey({ id: res.id, pem: res.private_key_pem })
      onChanged()
    } catch (e: any) {
      alert(e.message ?? 'Renewal failed')
    } finally {
      setRenewing(false)
    }
  }

  const toggleAutoRenew = async () => {
    const next = !autoRenew
    const days = Math.max(1, parseInt(autoRenewDays, 10) || 30)
    try {
      await api.setAutoRenew(cert.id, next, days)
      setAutoRenew(next)
      setAutoRenewDays(String(days))
      onChanged()
    } catch (e: any) {
      alert(e.message ?? 'Could not change auto-renewal')
    }
  }

  const doRevoke = async () => {
    if (!confirm(`Revoke certificate '${cert.common_name}'? This cannot be undone.`)) return
    setRevoking(true)
    try {
      await api.revokeCertificate(cert.id, reason, reasonCode)
      onChanged()
      onClose()
    } finally {
      setRevoking(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 py-8 px-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 max-w-2xl w-full max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white truncate pr-4">{cert.common_name}</h3>
          <span className={`shrink-0 text-xs px-2 py-0.5 rounded-full font-medium capitalize ${STATUS_STYLES[cert.status]}`}>{cert.status}</span>
        </div>
        <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm mb-4">
          <div><span className="text-white">Source</span><p className="text-white capitalize">{cert.source}</p></div>
          <div><span className="text-white">Serial</span><p className="text-white font-mono text-xs break-all">{cert.serial_number}</p></div>
          <div><span className="text-white">Not Before</span><p className="text-white">{fmtDate(cert.not_before)}</p></div>
          <div><span className="text-white">Not After</span><p className="text-white">{fmtDate(cert.not_after)}</p></div>
          <div><span className="text-white">Key</span><p className="text-white">{cert.key_algorithm?.toUpperCase()} {cert.key_size}{cert.key_encrypted ? ' 🔒' : ''}</p></div>
          <div><span className="text-white">Signature</span><p className="text-white">{cert.signature_algorithm}</p></div>
          <div className="col-span-2"><span className="text-white">Issuer</span><p className="text-white text-xs font-mono break-all">{cert.issuer}</p></div>
          <div className="col-span-2"><span className="text-white">Subject</span><p className="text-white text-xs font-mono break-all">{cert.subject}</p></div>
          {cert.san.length > 0 && (
            <div className="col-span-2"><span className="text-white">SANs</span><p className="text-white text-xs font-mono break-all">{cert.san.join(', ')}</p></div>
          )}
          {cert.host && <div><span className="text-white">Host</span><p className="text-white font-mono">{cert.host}:{cert.port}</p></div>}
          <div className="col-span-2"><span className="text-white">Fingerprint (SHA-256)</span><p className="text-white text-xs font-mono break-all">{cert.fingerprint_sha256}</p></div>
          {cert.revoked_at && (
            <div className="col-span-2"><span className="text-red-400">Revoked</span><p className="text-white text-xs">
              {fmtDate(cert.revoked_at)}
              {cert.revoked_reason_code ? ` — ${REVOCATION_REASONS.find(r => r.value === cert.revoked_reason_code)?.label ?? cert.revoked_reason_code}` : ''}
              {cert.revoked_reason ? ` (${cert.revoked_reason})` : ''}
            </p></div>
          )}
          {cert.renewed_to_id && (
            <div className="col-span-2"><span className="text-white">Renewed</span><p className="text-white text-xs">Superseded by certificate #{cert.renewed_to_id} — still valid until it expires, and not revoked</p></div>
          )}
          {cert.renewed_from_id && (
            <div className="col-span-2"><span className="text-white">Renewal of</span><p className="text-white text-xs">Replaces certificate #{cert.renewed_from_id}</p></div>
          )}
        </div>

        <div className="grid grid-flow-col grid-rows-2 gap-2 w-fit mb-4">
          <button onClick={() => viewPem('pem')} className="text-xs bg-gray-800 hover:bg-gray-700 text-white border border-gray-700 rounded px-3 py-1.5 transition-colors">View Certificate PEM</button>
          <button onClick={() => downloadPem('pem')} className="text-xs bg-gray-800 hover:bg-gray-700 text-sky-300 border border-sky-800/60 rounded px-3 py-1.5 transition-colors">Download Certificate</button>
          <button onClick={() => viewPem('chain')} className="text-xs bg-gray-800 hover:bg-gray-700 text-white border border-gray-700 rounded px-3 py-1.5 transition-colors">View Chain PEM</button>
          <button onClick={() => downloadPem('chain')} className="text-xs bg-gray-800 hover:bg-gray-700 text-sky-300 border border-sky-800/60 rounded px-3 py-1.5 transition-colors">Download Chain</button>
          {isAdmin && cert.has_private_key && (
            <>
              <button onClick={() => revealSecret('key')} className="text-xs bg-gray-800 hover:bg-gray-700 text-amber-300 border border-amber-800/60 rounded px-3 py-1.5 transition-colors">Reveal Private Key</button>
              <button onClick={() => downloadSecret('key')} className="text-xs bg-gray-800 hover:bg-gray-700 text-amber-300 border border-amber-800/60 rounded px-3 py-1.5 transition-colors">Download Private Key</button>
            </>
          )}
          {isAdmin && cert.has_passcode && (
            <>
              <button onClick={() => revealSecret('passcode')} className="text-xs bg-gray-800 hover:bg-gray-700 text-amber-300 border border-amber-800/60 rounded px-3 py-1.5 transition-colors">Reveal Passcode</button>
              <button onClick={() => downloadSecret('passcode')} className="text-xs bg-gray-800 hover:bg-gray-700 text-amber-300 border border-amber-800/60 rounded px-3 py-1.5 transition-colors">Download Passcode</button>
            </>
          )}
        </div>

        {isAdmin && cert.has_private_key && cert.key_encrypted && (
          <p className="text-xs text-amber-300/90 mb-4">🔒 This private key is passphrase-protected — the exported PEM is encrypted and needs the passphrase set at issue time to install. pktCert doesn't store that passphrase.</p>
        )}

        {pem && (
          <div className="mb-4">
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs text-white capitalize">{pem.fmt} PEM</label>
              <button onClick={() => copyToClipboard(pem.text)} className="text-xs text-sky-400 hover:text-sky-300">Copy</button>
            </div>
            <textarea readOnly value={pem.text} rows={8}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white resize-none" />
          </div>
        )}

        {isAdmin && renewable && cert.status !== 'revoked' && !cert.renewed_to_id && (
          <div className="border-t border-gray-800 pt-4 mb-4">
            <div className="flex items-center gap-3 flex-wrap">
              <button onClick={doRenew} disabled={renewing}
                className="text-sm bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg px-4 py-2 transition-colors">
                {renewing ? 'Renewing…' : 'Renew Now'}
              </button>
              <label className="flex items-center gap-2 text-xs text-white">
                <input type="checkbox" checked={autoRenew} onChange={toggleAutoRenew} className="accent-sky-500" />
                Auto-renew within
              </label>
              <input type="number" min={1} max={365} value={autoRenewDays}
                onChange={e => setAutoRenewDays(e.target.value)}
                onBlur={() => { if (autoRenew) toggleAutoRenew() }}
                className="w-16 bg-gray-800 border border-gray-700 rounded-lg px-2 py-1 text-xs text-white" />
              <span className="text-xs text-white">days of expiry</span>
            </div>
            <p className="text-xs text-white/70 mt-2">
              Renewing issues a new certificate and a new private key from the same CA and template.
              The current one is marked superseded but stays valid and is <span className="text-amber-300">not</span> revoked,
              so the running service keeps working until you install the replacement — revoke it yourself once you have.
            </p>
          </div>
        )}

        {renewedKey && (
          <div className="mb-4 border border-sky-800/60 rounded-lg p-3">
            <p className="text-xs text-sky-300 mb-2">
              Renewed as certificate #{renewedKey.id}. This is the only time the new private key is shown without
              re-entering your password — download it now, or retrieve it later from the new certificate's detail view.
            </p>
            {renewedKey.pem && (
              <div className="flex items-center gap-3">
                <button onClick={() => copyToClipboard(renewedKey.pem!)} className="text-xs text-sky-400 hover:text-sky-300">Copy key</button>
                <button onClick={() => downloadFile(`${filenameBase}-renewed-key.pem`, renewedKey.pem!)} className="text-xs text-sky-400 hover:text-sky-300">Download key</button>
              </div>
            )}
          </div>
        )}

        {isAdmin && cert.status !== 'revoked' && (
          <div className="border-t border-gray-800 pt-4 space-y-2">
            <div>
              <label className="block text-xs text-white mb-1">Revocation reason (published in the CRL)</label>
              <select value={reasonCode} onChange={e => setReasonCode(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white">
                {REVOCATION_REASONS.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
              </select>
              <p className="text-xs text-white/70 mt-1">
                Relying parties act on this: <span className="text-amber-300">key compromise</span> casts doubt on
                everything that key ever signed, while superseded or cessation of operation are routine. The note
                below is for your own records and never leaves pktCert.
              </p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <input value={reason} onChange={e => setReason(e.target.value)} placeholder="Internal note (optional)"
                className="flex-1 min-w-[200px] bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white" />
              <button onClick={doRevoke} disabled={revoking}
                className="text-sm bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white rounded-lg px-4 py-2 transition-colors">
                {revoking ? 'Revoking…' : 'Revoke'}
              </button>
            </div>
          </div>
        )}

        <button onClick={onClose} className="w-full mt-4 px-4 py-2 text-sm border border-gray-700 hover:border-gray-500 text-white rounded-lg transition-colors">Close</button>
      </div>
      {pending && <ConfirmPasswordModal title={pending.title} description={pending.description} onConfirm={pending.run} onClose={() => setPending(null)} />}
    </div>
  )
}

// ── Upload External Certificate modal ──────────────────────────────────────

function UploadModal({ onClose, onUploaded }: { onClose: () => void; onUploaded: () => void }) {
  const [certFile, setCertFile] = useState<File | null>(null)
  const [keyFile, setKeyFile] = useState<File | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [passcode, setPasscode] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const isPfx = certFile ? /\.(pfx|p12)$/i.test(certFile.name) : false

  const submit = async () => {
    if (!certFile) return
    setSaving(true)
    setError('')
    try {
      await api.uploadExternalCertificate({ certFile, keyFile: keyFile ?? undefined, passphrase, passcode })
      onUploaded()
      onClose()
    } catch (e: any) {
      setError(e.message ?? 'Failed to upload certificate')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 py-8 px-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 max-w-lg w-full max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-semibold text-white mb-2">Upload External Certificate</h3>
        <p className="text-sm text-white mb-4">For certificates issued by an outside CA (purchased, Let's Encrypt, etc). Upload a PEM certificate (+ optional separate key), or a single PKCS#12 (.pfx/.p12) bundle. Any private key and install passcode are encrypted at rest and only ever revealed after re-confirming your password.</p>
        <div className="space-y-4">
          <div>
            <label className="block text-xs text-white mb-1">Certificate file (.pem/.crt/.cer or .pfx/.p12)</label>
            <input type="file" accept=".pem,.crt,.cer,.pfx,.p12"
              onChange={e => setCertFile(e.target.files?.[0] ?? null)}
              className="block w-full text-sm text-white file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-gray-800 file:text-white hover:file:bg-gray-700 file:cursor-pointer" />
          </div>
          {!isPfx && (
            <div>
              <label className="block text-xs text-white mb-1">Private key file (.pem, optional)</label>
              <input type="file" accept=".pem,.key"
                onChange={e => setKeyFile(e.target.files?.[0] ?? null)}
                className="block w-full text-sm text-white file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-gray-800 file:text-white hover:file:bg-gray-700 file:cursor-pointer" />
            </div>
          )}
          {isPfx && (
            <div>
              <label className="block text-xs text-white mb-1">PFX/P12 export passphrase</label>
              <input type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500" />
            </div>
          )}
          <div>
            <label className="block text-xs text-white mb-1">Install / use passcode (optional)</label>
            <input value={passcode} onChange={e => setPasscode(e.target.value)} placeholder="Anything ops needs to install or use this certificate"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500" />
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex items-center gap-3 pt-1">
            <button onClick={submit} disabled={saving || !certFile}
              className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-5 py-2 transition-colors">
              {saving ? 'Uploading…' : 'Upload'}
            </button>
            <button onClick={onClose} className="text-white hover:text-white text-sm border border-gray-700 rounded-lg px-4 py-2 transition-colors">Cancel</button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Certificates() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [params, setParams] = useSearchParams()
  const [certs, setCerts] = useState<Certificate[]>([])
  const [cas, setCas] = useState<CertificateAuthority[]>([])
  const [templates, setTemplates] = useState<CertTemplate[]>([])
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState(params.get('status') ?? '')
  const [sourceFilter, setSourceFilter] = useState('')
  const [search, setSearch] = useState(params.get('search') ?? '')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<Certificate | null>(null)
  const [showIssue, setShowIssue] = useState(false)
  const [showUpload, setShowUpload] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [c, caList, tmplList] = await Promise.all([
        api.getCertificates({ limit: 2000 }),
        api.getCas(),
        api.getTemplates(),
      ])
      setCerts(c); setCas(caList); setTemplates(tmplList)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const filtered = useMemo(() => certs.filter(c =>
    (!statusFilter || c.status === statusFilter) &&
    (!sourceFilter || c.source === sourceFilter) &&
    (!search || c.common_name.toLowerCase().includes(search.toLowerCase()) || (c.host ?? '').toLowerCase().includes(search.toLowerCase()))
  ), [certs, statusFilter, sourceFilter, search])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const pageClamped = Math.min(page, totalPages)
  const paged = filtered.slice((pageClamped - 1) * PAGE_SIZE, pageClamped * PAGE_SIZE)

  const setStatus = (v: string) => { setStatusFilter(v); setPage(1); setParams(v ? { status: v } : {}) }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-white">Certificates</h1>
          <HelpButton title="Certificates — How It Works">
            <p>The unified inventory of every certificate pktCert knows about — discovered by an active scan of a Scan Target, found via Certificate Transparency search, or issued by one of your internal CAs.</p>
            <p><span className="text-gray-300 font-medium">Status</span> updates automatically: valid → expiring (within 30 days) → expired, or revoked when you revoke it manually. Revocation is terminal and feeds each CA's CRL.</p>
            <p><span className="text-gray-300 font-medium">Renewing</span> a certificate pktCert issued creates a replacement from the same CA and template, with a new private key, and marks the old one <em>superseded</em>. Superseded certificates stay valid and are not revoked — they just stop raising expiry alerts, since the replacement already exists. Turn on auto-renew to have that happen automatically inside a chosen window; you still have to install the new key.</p>
          </HelpButton>
        </div>
        {isAdmin && (
          <div className="flex items-center gap-2">
            <button onClick={() => setShowUpload(true)}
              className="bg-gray-700 hover:bg-gray-600 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors">
              + Upload External Certificate
            </button>
            <button onClick={() => setShowIssue(true)}
              className="bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors">
              + Issue Certificate
            </button>
          </div>
        )}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <input value={search} onChange={e => { setSearch(e.target.value); setPage(1) }} placeholder="Search common name or host…"
          className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white placeholder-gray-600 w-64 focus:outline-none focus:ring-1 focus:ring-sky-500" />
        <select value={statusFilter} onChange={e => setStatus(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white focus:outline-none focus:ring-1 focus:ring-sky-500">
          <option value="">All statuses</option>
          <option value="valid">Valid</option>
          <option value="expiring">Expiring</option>
          <option value="expired">Expired</option>
          <option value="revoked">Revoked</option>
          <option value="superseded">Superseded</option>
        </select>
        <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(1) }}
          className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-white focus:outline-none focus:ring-1 focus:ring-sky-500">
          <option value="">All sources</option>
          <option value="scan">Scanned</option>
          <option value="ct">CT Search</option>
          <option value="issued">Issued</option>
          <option value="external">External / Uploaded</option>
        </select>
        <span className="text-xs text-white ml-auto">{filtered.length} certificate{filtered.length !== 1 ? 's' : ''}</span>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Common Name</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Source</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Issuer</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-white">Expires</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {loading && <tr><td colSpan={5} className="px-4 py-8 text-center text-sm text-white">Loading…</td></tr>}
            {!loading && paged.map(c => (
              <tr key={c.id} onClick={() => setSelected(c)} className="hover:bg-gray-800/30 transition-colors cursor-pointer">
                <td className="px-4 py-3 font-mono text-white truncate max-w-xs">{c.common_name}</td>
                <td className="px-4 py-3"><span className={`text-xs px-2 py-0.5 rounded-full capitalize ${STATUS_STYLES[c.status]}`}>{c.status}</span></td>
                <td className="px-4 py-3 text-white text-xs capitalize">{c.source}</td>
                <td className="px-4 py-3 text-white text-xs truncate max-w-xs">{c.issuer}</td>
                <td className="px-4 py-3 text-white">{fmtDate(c.not_after)}</td>
              </tr>
            ))}
            {!loading && paged.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-sm text-white">
                {certs.length === 0 ? 'No certificates yet — add a Scan Target or issue one.' : 'No certificates match this filter'}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center">
          <Pagination page={pageClamped} totalPages={totalPages} onChange={setPage} />
        </div>
      )}

      {selected && <DetailModal cert={selected} isAdmin={isAdmin} onClose={() => setSelected(null)} onChanged={load} />}
      {showIssue && <IssueModal cas={cas.filter(c => c.status === 'active')} templates={templates} onClose={() => setShowIssue(false)} onIssued={load} />}
      {showUpload && <UploadModal onClose={() => setShowUpload(false)} onUploaded={load} />}
    </div>
  )
}
