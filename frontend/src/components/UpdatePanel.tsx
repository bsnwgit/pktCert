import { useCallback, useEffect, useState } from 'react'
import { getToken } from '../api/client'

// Settings → System → Updates. Talks to /api/system/update-* (app/self_update.py):
// check GitHub for a newer release, apply it, and wait for the service to come
// back. Mode / window / token are admin-only; status is shown to everyone.

interface UpdateStatus {
  current_version: string
  latest_tag: string | null
  latest_url: string | null
  update_available: boolean
  checked_at: string | null
  last_error: string
  last_applied_tag: string | null
  last_applied_at: string | null
  mode: 'manual' | 'auto'
  window_start: string
  window_end: string
  token_set: boolean
  repo: string
  can_apply: boolean
}

async function call<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const token = getToken()
  const res = await fetch(`/api/system${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || res.statusText)
  }
  return res.json()
}

const ago = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : 'never')

export default function UpdatePanel({ isAdmin }: { isAdmin: boolean }) {
  const [st, setSt] = useState<UpdateStatus | null>(null)
  const [busy, setBusy] = useState<'' | 'check' | 'apply' | 'save'>('')
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [restarting, setRestarting] = useState(false)
  const [mode, setMode] = useState<'manual' | 'auto'>('manual')
  const [start, setStart] = useState('02:00')
  const [end, setEnd] = useState('04:00')
  const [token, setToken] = useState('')

  const load = useCallback(async () => {
    try {
      const s = await call<UpdateStatus>('/update-status')
      setSt(s)
      setMode(s.mode)
      setStart(s.window_start)
      setEnd(s.window_end)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load update status')
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function check() {
    setBusy('check'); setError(''); setNote('')
    try {
      const s = await call<UpdateStatus>('/update-check', 'POST')
      setSt(s)
      if (!s.update_available && !s.last_error) setNote('You are on the latest version.')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Check failed')
    } finally { setBusy('') }
  }

  async function save() {
    setBusy('save'); setError(''); setNote('')
    try {
      const s = await call<UpdateStatus>('/update-config', 'PUT', {
        mode, window_start: start, window_end: end,
        // Blank means "leave the stored token alone"; clearing is its own button.
        ...(token ? { github_token: token } : {}),
      })
      setSt(s); setToken(''); setNote('Saved.')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed')
    } finally { setBusy('') }
  }

  async function clearToken() {
    setBusy('save'); setError(''); setNote('')
    try {
      setSt(await call<UpdateStatus>('/update-config', 'PUT', { github_token: '' }))
      setNote('GitHub token cleared.')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not clear the token')
    } finally { setBusy('') }
  }

  async function apply() {
    if (!window.confirm(`Update to ${st?.latest_tag}? The service restarts and is unavailable for a few seconds.`)) return
    setBusy('apply'); setError(''); setNote('')
    try {
      await call('/update-apply', 'POST')
      setRestarting(true)
      // Give the process time to actually exit, then wait for it to answer again.
      await new Promise(r => setTimeout(r, 5000))
      for (let i = 0; i < 60; i++) {
        try {
          const res = await fetch('/api/system/update-status', { headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {} })
          if (res.status < 500) { window.location.reload(); return }
        } catch { /* still down */ }
        await new Promise(r => setTimeout(r, 2000))
      }
      setRestarting(false)
      setError('The service did not come back within two minutes — check the server.')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Update failed')
    } finally { setBusy('') }
  }

  const input = 'bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500'
  const button = 'px-3 py-1.5 text-sm rounded-lg text-white disabled:opacity-50'

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-800">
        <h2 className="text-sm font-semibold text-white">Updates</h2>
      </div>
      <div className="px-6 py-4 space-y-4 text-sm">
        {!st && !error && <p className="text-gray-400">Loading…</p>}
        {st && (
          <>
            <div className="grid grid-cols-3 gap-4">
              <p className="text-white font-medium">Installed</p>
              <p className="col-span-2 text-white font-mono">v{st.current_version}</p>
              <p className="text-white font-medium">Latest release</p>
              <p className="col-span-2 font-mono">
                {st.latest_tag
                  ? <a href={st.latest_url ?? '#'} target="_blank" rel="noreferrer" className="text-blue-400 hover:text-blue-300">{st.latest_tag}</a>
                  : <span className="text-gray-400">—</span>}
                {st.update_available && <span className="ml-3 text-yellow-400">update available</span>}
              </p>
              <p className="text-white font-medium">Last checked</p>
              <p className="col-span-2 text-white">{ago(st.checked_at)}</p>
              {st.last_applied_tag && (<>
                <p className="text-white font-medium">Last applied</p>
                <p className="col-span-2 text-white">{st.last_applied_tag} · {ago(st.last_applied_at)}</p>
              </>)}
            </div>

            {restarting && <p className="text-yellow-400">Update applied — restarting. This page reloads when the service is back.</p>}
            {st.last_error && <p className="text-red-400">{st.last_error}</p>}
            {error && <p className="text-red-400">{error}</p>}
            {note && <p className="text-green-400">{note}</p>}
            {isAdmin && !st.can_apply && (
              <p className="text-yellow-400">This install is a git checkout, so updates can be checked but not applied here.</p>
            )}

            {isAdmin && (
              <div className="flex gap-2">
                <button className={`${button} bg-gray-700 hover:bg-gray-600`} disabled={busy !== '' || restarting} onClick={check}>
                  {busy === 'check' ? 'Checking…' : 'Check for updates'}
                </button>
                {st.update_available && st.can_apply && (
                  <button className={`${button} bg-sky-600 hover:bg-sky-500`} disabled={busy !== '' || restarting} onClick={apply}>
                    {busy === 'apply' ? 'Updating…' : `Update to ${st.latest_tag}`}
                  </button>
                )}
              </div>
            )}

            {isAdmin && (
              <div className="border-t border-gray-800 pt-4 space-y-3">
                <div className="grid grid-cols-3 gap-4 items-center">
                  <label className="text-white font-medium" htmlFor="upd-mode">Update mode</label>
                  <select id="upd-mode" className={`${input} col-span-2`} value={mode} onChange={e => setMode(e.target.value as 'manual' | 'auto')}>
                    <option value="manual">Manual — only when I press Update</option>
                    <option value="auto">Automatic — inside the window below</option>
                  </select>
                  {mode === 'auto' && (<>
                    <label className="text-white font-medium">Update window</label>
                    <div className="col-span-2 flex items-center gap-2">
                      <input type="time" className={input} value={start} onChange={e => setStart(e.target.value)} />
                      <span className="text-gray-400">to</span>
                      <input type="time" className={input} value={end} onChange={e => setEnd(e.target.value)} />
                    </div>
                  </>)}
                  <label className="text-white font-medium" htmlFor="upd-token">GitHub token</label>
                  <div className="col-span-2">
                    <input id="upd-token" type="password" autoComplete="off" className={`${input} w-full`} value={token}
                      onChange={e => setToken(e.target.value)}
                      placeholder={st.token_set ? 'Set — type to replace' : 'Only needed for a private repository'} />
                    {st.token_set && (
                      <button className="mt-1 text-xs text-blue-400 hover:text-blue-300" onClick={clearToken} disabled={busy !== ''}>Clear stored token</button>
                    )}
                  </div>
                </div>
                <button className={`${button} bg-sky-600 hover:bg-sky-500`} disabled={busy !== ''} onClick={save}>
                  {busy === 'save' ? 'Saving…' : 'Save'}
                </button>
                <p className="text-xs text-gray-400">
                  Checks <span className="font-mono">{st.repo}</span> hourly. An update replaces the application files only — your configuration, database and logs are never touched.
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
