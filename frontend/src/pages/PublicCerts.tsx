// Settings → Public Certificates. Obtains certificates from a publicly-trusted
// CA over ACME, so the result is trusted natively with nothing to install.
//
// This is the opposite direction from Enrolment. There, pktCert *is* the CA and
// internal hosts enrol against it; here pktCert is the client, and the issuer
// is Let's Encrypt or whichever ACME CA the operator points it at. An internal
// root can never be publicly trusted, so anything the outside world has to
// trust has to be issued from outside.
//
// Three things are configured, deliberately separately, because in practice
// they belong to different people: the DNS credential that proves a zone, the
// account at the CA, and the names themselves.

import { useCallback, useEffect, useState } from 'react'
import {
  api, DnsProvider, DnsProviderType, PublicAcmeAccount,
} from '../api/client'
import HelpButton from '../components/HelpButton'

const INPUT = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500'
const BTN = 'bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors'
const CARD = 'bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-4'

function fmtDate(ts: string | null): string {
  if (!ts) return '—'
  const utc = ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z'
  return new Date(utc).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export default function PublicCerts() {
  const [types, setTypes] = useState<DnsProviderType[]>([])
  const [directories, setDirectories] = useState<{ key: string; url: string }[]>([])
  const [providers, setProviders] = useState<DnsProvider[]>([])
  const [accounts, setAccounts] = useState<PublicAcmeAccount[]>([])
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [issuing, setIssuing] = useState(false)

  // DNS provider form
  const [dnsName, setDnsName] = useState('')
  const [dnsType, setDnsType] = useState('')
  const [dnsCredential, setDnsCredential] = useState('')

  // Account form
  const [accName, setAccName] = useState('')
  const [accDirectory, setAccDirectory] = useState('')
  const [accEmail, setAccEmail] = useState('')
  const [accEabKid, setAccEabKid] = useState('')
  const [accEabKey, setAccEabKey] = useState('')
  const [registering, setRegistering] = useState(false)

  // Certificate form
  const [reqName, setReqName] = useState('')
  const [reqAccount, setReqAccount] = useState<number | ''>('')
  const [reqProvider, setReqProvider] = useState<number | ''>('')
  const [reqNames, setReqNames] = useState('')
  const [reqRenewDays, setReqRenewDays] = useState('30')

  const load = useCallback(async () => {
    try {
      const [t, d, p, a] = await Promise.all([
        api.getDnsProviderTypes(), api.getAcmeDirectories(), api.getDnsProviders(),
        api.getPublicAcmeAccounts(),
      ])
      setTypes(t); setDirectories(d); setProviders(p); setAccounts(a)
      if (!dnsType && t.length) setDnsType(t[0].name)
      if (!accDirectory && d.length) setAccDirectory(d.find(x => x.key === 'letsencrypt-staging')?.url ?? d[0].url)
    } catch (e: any) { setError(e.message ?? 'Could not load public certificate settings') }
  }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  const act = async (fn: () => Promise<any>, ok: string) => {
    setError(null); setNotice(null)
    try { await fn(); setNotice(ok); await load() }
    catch (e: any) { setError(e.message ?? 'That did not work') }
  }

  const selectedType = types.find(t => t.name === dnsType)
  const isProduction = (a: PublicAcmeAccount) => a.environment === 'production'

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <h2 className="text-lg font-semibold text-white">Public Certificates</h2>
        <HelpButton title="Public Certificates — How It Works">
          <p>Your internal CA issues certificates that anyone who has installed its root will trust. This page is for the other case: a name that has to be trusted <em>natively</em>, by people who will never install anything.</p>
          <p>That trust comes from the issuing CA being in browser and operating-system root stores. An internal root cannot get there — it takes an audit programme, not a setting — so a natively-trusted certificate has to be issued by a CA that is already in those stores. pktCert asks one for you, over the same ACME protocol it serves internally.</p>
          <p><span className="text-gray-300 font-medium">Names must be real.</span> A public CA only issues for a publicly registered domain. Internal-only suffixes like <code className="text-gray-300">.lan</code> or <code className="text-gray-300">.local</code> are refused — they aren't yours to prove.</p>
          <p><span className="text-gray-300 font-medium">Validation is over DNS.</span> pktCert publishes a <code className="text-gray-300">_acme-challenge</code> TXT record, the CA reads it, and the record is removed again. That's why a DNS credential is needed — and it's also why the host itself never has to be reachable from the internet. A server on a private address can hold a publicly-trusted certificate perfectly well.</p>
          <p>DNS is also the only way to get a <span className="text-gray-300 font-medium">wildcard</span>. One <code className="text-gray-300">*.example.com</code> covers every internal service under that name.</p>
          <p><span className="text-gray-300 font-medium">Start on staging.</span> Let's Encrypt's production limits are strict and count failures as well as successes; getting locked out is measured in hours to days. Prove the whole path on staging first — those certificates are not trusted, which is the point — then create a production account.</p>
          <p>Unlike internal ACME enrolment, pktCert generates and holds the private key here, so it genuinely renews these on its own. Installing the renewed certificate on whatever serves it is still a separate step.</p>
        </HelpButton>
      </div>

      {error && <div className="bg-red-900/20 border border-red-800/40 rounded-xl p-3 text-sm text-red-300">{error}</div>}
      {notice && <div className="bg-emerald-900/20 border border-emerald-800/40 rounded-xl p-3 text-sm text-emerald-300">{notice}</div>}

      {/* ── DNS providers ─────────────────────────────────────────────── */}
      <div className={CARD}>
        <div>
          <h3 className="text-sm font-semibold text-white">DNS provider</h3>
          <p className="text-xs text-slate-400 mt-1">
            The credential that lets pktCert publish the challenge record. It can repoint your
            domain, so scope it as narrowly as your provider allows.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs text-white mb-1">Label</label>
            <input value={dnsName} onChange={e => setDnsName(e.target.value)} placeholder="Main DNS" className={INPUT} />
          </div>
          <div>
            <label className="block text-xs text-white mb-1">Provider</label>
            <select value={dnsType} onChange={e => setDnsType(e.target.value)} className={INPUT}>
              {types.length === 0 && <option value="">None available</option>}
              {types.map(t => <option key={t.name} value={t.name}>{t.label}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-white mb-1">Credential</label>
            <input value={dnsCredential} onChange={e => setDnsCredential(e.target.value)}
              type="password" autoComplete="off" placeholder="API token" className={INPUT} />
          </div>
        </div>
        {selectedType && <p className="text-xs text-slate-400">{selectedType.credential_help}</p>}
        <button className={BTN} disabled={!dnsName.trim() || !dnsType || !dnsCredential.trim()}
          onClick={() => act(async () => {
            await api.createDnsProvider({ name: dnsName.trim(), provider: dnsType, credential: dnsCredential.trim() })
            setDnsName(''); setDnsCredential('')
          }, 'DNS provider saved')}>Add provider</button>

        {providers.length > 0 && (
          <div className="space-y-2">
            {providers.map(p => (
              <div key={p.id} className="flex items-center justify-between flex-wrap gap-2 border-t border-gray-800 pt-2">
                <div className="text-sm text-white">
                  {p.name} <span className="text-slate-400 text-xs">· {p.provider} · last used {fmtDate(p.last_used_at)}</span>
                  {p.last_error && <p className="text-xs text-red-300 mt-0.5">{p.last_error}</p>}
                </div>
                <div className="flex gap-3">
                  <button className="text-xs text-sky-400 hover:text-sky-300"
                    onClick={() => act(async () => {
                      const r = await api.testDnsProvider(p.id)
                      setNotice(`${p.name}: ${r.detail}`)
                    }, `${p.name} reachable`)}>Test</button>
                  <button className="text-xs text-red-400 hover:text-red-300"
                    onClick={() => act(() => api.deleteDnsProvider(p.id), 'Provider removed')}>Delete</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── CA accounts ───────────────────────────────────────────────── */}
      <div className={CARD}>
        <div>
          <h3 className="text-sm font-semibold text-white">Certificate authority account</h3>
          <p className="text-xs text-slate-400 mt-1">
            Registers an account key with the CA. Start on staging — production limits count failures.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-white mb-1">Label</label>
            <input value={accName} onChange={e => setAccName(e.target.value)} placeholder="Let's Encrypt staging" className={INPUT} />
          </div>
          <div>
            <label className="block text-xs text-white mb-1">Directory</label>
            <select value={accDirectory} onChange={e => setAccDirectory(e.target.value)} className={INPUT}>
              {directories.map(d => <option key={d.key} value={d.url}>{d.key}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-white mb-1">Contact email (optional)</label>
            <input value={accEmail} onChange={e => setAccEmail(e.target.value)} placeholder="ops@example.com" className={INPUT} />
            <p className="text-xs text-slate-400 mt-1">Where the CA sends expiry warnings if renewal ever stops.</p>
          </div>
          <div>
            <label className="block text-xs text-white mb-1">External account binding (only some CAs)</label>
            <div className="flex gap-2">
              <input value={accEabKid} onChange={e => setAccEabKid(e.target.value)} placeholder="key id" className={INPUT} />
              <input value={accEabKey} onChange={e => setAccEabKey(e.target.value)} type="password"
                autoComplete="off" placeholder="HMAC key" className={INPUT} />
            </div>
            <p className="text-xs text-slate-400 mt-1">Let's Encrypt doesn't use this. ZeroSSL and Google do.</p>
          </div>
        </div>
        <button className={BTN} disabled={registering || !accName.trim() || !accDirectory}
          onClick={() => act(async () => {
            setRegistering(true)
            try {
              await api.createPublicAcmeAccount({
                name: accName.trim(), directory_url: accDirectory,
                environment: accDirectory.includes('staging') ? 'staging' : 'production',
                contact_email: accEmail.trim(), eab_kid: accEabKid.trim(), eab_hmac_key: accEabKey.trim(),
              })
              setAccName(''); setAccEmail(''); setAccEabKid(''); setAccEabKey('')
            } finally { setRegistering(false) }
          }, 'Account registered with the CA')}>
          {registering ? 'Registering…' : 'Register account'}
        </button>

        {accounts.length > 0 && (
          <div className="space-y-2">
            {accounts.map(a => (
              <div key={a.id} className="flex items-center justify-between flex-wrap gap-2 border-t border-gray-800 pt-2">
                <div className="text-sm text-white">
                  {a.name}{' '}
                  <span className={isProduction(a) ? 'text-amber-300 text-xs' : 'text-slate-400 text-xs'}>
                    · {a.environment}
                  </span>
                  <p className="text-xs text-slate-400 mt-0.5 break-all">{a.directory_url}</p>
                </div>
                <button className="text-xs text-red-400 hover:text-red-300"
                  onClick={() => act(() => api.deletePublicAcmeAccount(a.id), 'Account removed')}>Delete</button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Managed certificates ──────────────────────────────────────── */}
      <div className={CARD}>
        <div>
          <h3 className="text-sm font-semibold text-white">Managed certificates</h3>
          <p className="text-xs text-slate-400 mt-1">
            The names pktCert keeps alive. One entry can cover several names, and a wildcard
            covers everything under it.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-white mb-1">Label</label>
            <input value={reqName} onChange={e => setReqName(e.target.value)} placeholder="Public web" className={INPUT} />
          </div>
          <div>
            <label className="block text-xs text-white mb-1">Names</label>
            <input value={reqNames} onChange={e => setReqNames(e.target.value)}
              placeholder="example.com, www.example.com, *.internal.example.com" className={INPUT} />
            <p className="text-xs text-slate-400 mt-1">Comma separated. Must be under a domain you own.</p>
          </div>
          <div>
            <label className="block text-xs text-white mb-1">Account</label>
            <select value={reqAccount} onChange={e => setReqAccount(Number(e.target.value))} className={INPUT}>
              <option value="">Select…</option>
              {accounts.map(a => <option key={a.id} value={a.id}>{a.name} ({a.environment})</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-white mb-1">DNS provider</label>
            <select value={reqProvider} onChange={e => setReqProvider(Number(e.target.value))} className={INPUT}>
              <option value="">Select…</option>
              {providers.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-white mb-1">Renew this many days before expiry</label>
            <input value={reqRenewDays} onChange={e => setReqRenewDays(e.target.value)} type="number" min={1} className={INPUT} />
            <p className="text-xs text-slate-400 mt-1">30 suits a 90-day certificate. Shorter lifetimes need a tighter window.</p>
          </div>
        </div>
        <button className={BTN} disabled={issuing || !reqName.trim() || !reqNames.trim() || !reqAccount || !reqProvider}
          onClick={() => act(async () => {
            setIssuing(true)
            try {
              const created = await api.createPublicCertRequest({
                name: reqName.trim(), account_id: Number(reqAccount), dns_provider_id: Number(reqProvider),
                identifiers: reqNames.split(',').map(s => s.trim()).filter(Boolean),
                renew_before_days: Number(reqRenewDays) || 30,
              })
              // Ordered straight away rather than left pending. Adding a name
              // here is a request for a certificate, and a second button that
              // must also be pressed is just a way to end up with a row that
              // looks configured and has nothing behind it.
              await api.issuePublicCert(created.id)
              setReqName(''); setReqNames('')
            } finally { setIssuing(false) }
          }, 'Certificate issued — manage it from the Certificates tab')}>
          {issuing ? 'Requesting…' : 'Request certificate'}
        </button>
        <p className="text-xs text-slate-400">
          Once issued it lives in the <span className="text-gray-300">Certificates</span> tab like every other
          certificate — renewal, replacement and revocation all happen there.
        </p>

      </div>
    </div>
  )
}
