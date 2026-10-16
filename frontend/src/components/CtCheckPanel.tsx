// Result of a crt.sh validation, shared by the certificate detail view and the
// CT Checks page.
import { CtCheckDetail, CtCheckResult, CtEntry, CtVerdict } from '../api/client'

export const CT_VERDICTS: Record<CtVerdict, { label: string; tone: string }> = {
  running: { label: 'Checking crt.sh…', tone: 'text-sky-300' },
  failed: { label: 'The check failed — nothing was concluded', tone: 'text-red-400' },
  logged: { label: 'Logged in Certificate Transparency', tone: 'text-emerald-400' },
  not_logged: { label: 'Not found in Certificate Transparency', tone: 'text-amber-300' },
  unexpected_found: { label: 'Certificates you may not know about', tone: 'text-red-400' },
  unavailable: { label: 'crt.sh could not be reached — nothing was checked', tone: 'text-amber-300' },
  inconclusive: { label: 'Inconclusive — crt.sh failed for some names', tone: 'text-amber-300' },
  not_applicable: { label: 'Nothing to check — no public names on this certificate', tone: 'text-white' },
}

function CtEntryRow({ e }: { e: CtEntry }) {
  return (
    <li className="text-xs text-white border border-gray-800 rounded px-2 py-1.5">
      <p className="font-mono break-all">{e.issuer}</p>
      <p className="text-white/70 break-all">{e.names.join(', ') || e.common_name}</p>
      <p className="text-white/70">
        valid until {e.not_after ?? 'unknown'} · logged {e.logged_at ?? 'unknown'}
        {e.crtsh_id && (
          <> · <a href={`https://crt.sh/?id=${e.crtsh_id}`} target="_blank" rel="noopener noreferrer"
            className="text-sky-400 hover:text-sky-300">crt.sh #{e.crtsh_id}</a></>
        )}
      </p>
    </li>
  )
}

export default function CtCheckPanel({ result }: { result: CtCheckResult }) {
  const v = CT_VERDICTS[result.verdict]
  return (
    <div className="mt-3 space-y-2">
      <p className={`text-sm font-medium ${v.tone}`}>{v.label}</p>
      {result.logged_entry && (
        <p className="text-xs text-white">
          First seen in the log {result.logged_entry.logged_at ?? 'at an unknown time'}
          {result.logged_entry.crtsh_id && (
            <> — <a href={`https://crt.sh/?id=${result.logged_entry.crtsh_id}`} target="_blank" rel="noopener noreferrer"
              className="text-sky-400 hover:text-sky-300">crt.sh #{result.logged_entry.crtsh_id}</a></>
          )}
        </p>
      )}
      {result.verdict === 'not_logged' && (
        <p className="text-xs text-white/70">
          Expected for certificates from a private CA. For a certificate from a public CA it is worth a look.
        </p>
      )}
      {result.unexpected.length > 0 && (
        <div>
          <p className="text-xs text-red-400 mb-1">
            {result.unexpected.length} unexpired certificate(s) for these names from an issuer other than this one,
            and not in your inventory:
          </p>
          <ul className="space-y-1">{result.unexpected.map((e, i) => <CtEntryRow key={i} e={e} />)}</ul>
        </div>
      )}
      {result.same_issuer.length > 0 && (
        <div>
          <p className="text-xs text-white/70 mb-1">
            {result.same_issuer.length} other unexpired certificate(s) from the same issuer, not in your inventory:
          </p>
          <ul className="space-y-1">{result.same_issuer.map((e, i) => <CtEntryRow key={i} e={e} />)}</ul>
        </div>
      )}
      {result.errors.length > 0 && (
        <ul className="text-xs text-amber-300 space-y-0.5">{result.errors.map((m, i) => <li key={i}>{m}</li>)}</ul>
      )}
      <p className="text-xs text-white/70">
        Searched: {result.names_checked.join(', ') || 'nothing'}.
        {result.names_skipped.length > 0 && <> Not sent (not public): {result.names_skipped.join(', ')}.</>}
        {result.names_over_limit.length > 0 && <> Not searched (limit of 10 names): {result.names_over_limit.join(', ')}.</>}
        {result.crtsh_url && (
          <> <a href={result.crtsh_url} target="_blank" rel="noopener noreferrer"
            className="text-sky-400 hover:text-sky-300">Open on crt.sh</a></>
        )}
      </p>
    </div>
  )
}

// A check's outcome in whatever state it is in. The full panel only exists once
// crt.sh has answered; before that there is nothing to show but the wait.
export function CtCheckOutcome({ check }: { check: Pick<CtCheckDetail, 'verdict' | 'result'> }) {
  if (check.verdict === 'running') {
    return <p className="text-xs text-sky-300">Checking crt.sh… this can take a minute or more for a large domain. You can leave this page; the result will appear in the history.</p>
  }
  if (check.verdict === 'failed') {
    return <p className="text-xs text-red-400">{check.result.error ?? 'The check failed.'}</p>
  }
  return <CtCheckPanel result={check.result as CtCheckResult} />
}
