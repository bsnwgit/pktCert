import { useCallback, useEffect, useState } from 'react'
import { api, CertRequest } from '../api/client'
import { useAuth } from '../store/auth'
import HelpButton from '../components/HelpButton'

const STATUS_STYLES: Record<string, string> = {
  pending: 'bg-amber-500/20 text-amber-400 border border-amber-500/40',
  approved: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40',
  rejected: 'bg-red-500/20 text-red-400 border border-red-500/40',
  cancelled: 'bg-gray-500/20 text-gray-400 border border-gray-500/40',
}

function fmtDate(ts: string | null): string {
  if (!ts) return '—'
  const utc = ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z'
  return new Date(utc).toLocaleString([], { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export default function Approvals() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [requests, setRequests] = useState<CertRequest[]>([])
  const [config, setConfig] = useState<{ issuance_approval_required: boolean; revocation_approval_required: boolean; admin_count: number; pending_count: number } | null>(null)
  const [statusFilter, setStatusFilter] = useState('pending')
  const [loading, setLoading] = useState(true)
  const [note, setNote] = useState<Record<number, string>>({})
  const [busy, setBusy] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [reqs, cfg] = await Promise.all([
        api.getApprovals(statusFilter ? { status: statusFilter } : undefined),
        api.getApprovalConfig(),
      ])
      setRequests(reqs)
      setConfig(cfg)
    } finally {
      setLoading(false)
    }
  }, [statusFilter])

  useEffect(() => { load() }, [load])

  const act = async (id: number, action: 'approve' | 'reject' | 'cancel') => {
    setBusy(id)
    setError(null)
    try {
      if (action === 'approve') await api.approveRequest(id, note[id] ?? '')
      else if (action === 'reject') await api.rejectRequest(id, note[id] ?? '')
      else await api.cancelRequest(id)
      await load()
    } catch (e: any) {
      setError(e.message ?? `Could not ${action} this request`)
    } finally {
      setBusy(null)
    }
  }

  const featureOff = config && !config.issuance_approval_required && !config.revocation_approval_required
  // Self-approval is refused, so a lone admin could raise requests and never be
  // able to action them. Say so before they find out the hard way.
  const soloAdmin = config && config.admin_count < 2 &&
    (config.issuance_approval_required || config.revocation_approval_required)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-white">Approvals</h1>
          <HelpButton title="Approvals — How It Works">
            <p>Separation of duties: when approval is required, issuing or revoking a certificate records a request here instead of acting immediately, and a <span className="text-gray-300 font-medium">different</span> admin approves it. The approval is what performs the operation — nothing is issued or revoked while a request sits pending.</p>
            <p>You cannot approve your own request. One person clicking twice isn't two pairs of eyes, and allowing it would make the control decorative — which is worse than not having it, because it still looks like a control in an audit.</p>
            <p>This is <span className="text-gray-300 font-medium">off by default</span> and is enabled per action under Settings → Cert Settings. A small team where everyone is trusted equally gains nothing from it and loses a step on every issuance.</p>
            <p>Withdrawing your own pending request is always allowed — cancelling can only ever prevent an action, never cause one.</p>
          </HelpButton>
        </div>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white">
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
          <option value="cancelled">Cancelled</option>
          <option value="">All</option>
        </select>
      </div>

      {featureOff && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-sm text-white">
          Approval is currently <span className="text-amber-300">not required</span> — certificates are issued and
          revoked immediately. Turn it on per action under Settings → Cert Settings. Anything already recorded here
          stays visible as history.
        </div>
      )}

      {soloAdmin && (
        <div className="bg-amber-900/20 border border-amber-800/40 rounded-xl p-4 text-sm text-amber-300">
          Approval is required, but this install has only one admin account. Since nobody can approve their own
          request, no request can ever be approved. Add a second admin, or turn approval off under
          Settings → Cert Settings.
        </div>
      )}

      {error && <div className="bg-red-900/20 border border-red-800/40 rounded-xl p-3 text-sm text-red-400">{error}</div>}

      {loading && <p className="text-sm text-white">Loading…</p>}

      {!loading && requests.length === 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center text-sm text-white">
          No {statusFilter || ''} requests.
        </div>
      )}

      <div className="space-y-3">
        {requests.map(r => {
          const mine = r.requested_by === user?.username
          return (
            <div key={r.id} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-white font-medium capitalize">{r.request_type}</span>
                    <span className="text-white truncate">
                      {r.request_type === 'issue' ? r.common_name : `certificate #${r.certificate_id}`}
                    </span>
                    <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${STATUS_STYLES[r.status]}`}>{r.status}</span>
                  </div>
                  <p className="text-xs text-white mt-1">
                    Requested by <span className="text-sky-300">{r.requested_by}</span> · {fmtDate(r.requested_at)}
                    {r.request_type === 'revoke' && r.reason_code && <> · reason: {r.reason_code}</>}
                  </p>
                  {r.sans.length > 0 && (
                    <p className="text-xs text-white/70 mt-0.5 font-mono break-all">SAN: {r.sans.join(', ')}</p>
                  )}
                  {r.justification && (
                    <p className="text-xs text-white/70 mt-1">Justification: {r.justification}</p>
                  )}
                  {r.status !== 'pending' && (
                    <p className="text-xs text-white/70 mt-1">
                      {r.status} by <span className="text-sky-300">{r.decided_by}</span> · {fmtDate(r.decided_at)}
                      {r.decision_note ? ` — ${r.decision_note}` : ''}
                      {r.resulting_certificate_id ? ` → certificate #${r.resulting_certificate_id}` : ''}
                    </p>
                  )}
                </div>

                {r.status === 'pending' && (
                  <div className="flex flex-col gap-2 items-end">
                    {isAdmin && !mine && (
                      <>
                        <input value={note[r.id] ?? ''} onChange={e => setNote({ ...note, [r.id]: e.target.value })}
                          placeholder="Decision note (optional)"
                          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white w-56" />
                        <div className="flex gap-2">
                          <button onClick={() => act(r.id, 'approve')} disabled={busy === r.id}
                            className="text-xs bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg px-3 py-1.5 transition-colors">
                            {busy === r.id ? '…' : 'Approve'}
                          </button>
                          <button onClick={() => act(r.id, 'reject')} disabled={busy === r.id}
                            className="text-xs bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white rounded-lg px-3 py-1.5 transition-colors">
                            Reject
                          </button>
                        </div>
                      </>
                    )}
                    {isAdmin && mine && (
                      <p className="text-xs text-amber-300/90 max-w-[16rem] text-right">
                        You raised this — another admin has to approve it.
                      </p>
                    )}
                    {(mine || isAdmin) && (
                      <button onClick={() => act(r.id, 'cancel')} disabled={busy === r.id}
                        className="text-xs text-white hover:text-white border border-gray-700 rounded-lg px-3 py-1.5 transition-colors">
                        Withdraw
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
