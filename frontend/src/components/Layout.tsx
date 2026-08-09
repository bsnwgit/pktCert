import { ReactNode, useState, useEffect } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../store/auth'
import { api } from '../api/client'
import clsx from 'clsx'
import AiAssistant from './AiAssistant'

function ChangePasswordModal({ onClose }: { onClose: () => void }) {
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (newPw.length < 6) { setError('New password must be at least 6 characters'); return }
    if (newPw !== confirmPw) { setError('Passwords do not match'); return }
    setSaving(true)
    setError('')
    try {
      await api.changeMyPassword(currentPw, newPw)
      setSuccess(true)
      setTimeout(onClose, 1200)
    } catch (e: any) {
      setError(e.message ?? 'Failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-sm p-6" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-white mb-5">Change Password</h2>
        {success ? (
          <p className="text-green-400 text-sm text-center py-4">Password updated successfully!</p>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="text-xs text-white block mb-1">Current Password</label>
              <input type="password" value={currentPw} onChange={e => setCurrentPw(e.target.value)} required autoFocus
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-sky-500" />
            </div>
            <div>
              <label className="text-xs text-white block mb-1">New Password</label>
              <input type="password" value={newPw} onChange={e => setNewPw(e.target.value)} required
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-sky-500" />
            </div>
            <div>
              <label className="text-xs text-white block mb-1">Confirm New Password</label>
              <input type="password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)} required
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-sky-500" />
            </div>
            {error && <p className="text-red-400 text-xs">{error}</p>}
            <div className="flex justify-end gap-3 pt-2">
              <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-white hover:text-white transition-colors">Cancel</button>
              <button type="submit" disabled={saving}
                className="px-4 py-2 text-sm bg-sky-600 hover:bg-sky-500 text-white rounded-lg transition-colors disabled:opacity-50">
                {saving ? 'Saving…' : 'Update Password'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

const NAV = [
  { to: '/',                        label: 'Dashboard',              icon: '◑', adminOnly: false },
  { to: '/certificates',            label: 'Certificates',           icon: '▤', adminOnly: false },
  { to: '/scan-targets',            label: 'Scan Targets',           icon: '⌕', adminOnly: false, dividerBefore: true },
  { to: '/certificate-authorities', label: 'Certificate Authorities', icon: '⛨', adminOnly: false },
  { to: '/templates',               label: 'Templates',              icon: '▦', adminOnly: false },
  { to: '/alerts',                  label: 'Alerts',                 icon: '△', adminOnly: false, dividerBefore: true },
  { to: '/logs',                    label: 'Logs',                   icon: '☰', adminOnly: false },
  { to: '/settings',                label: 'Settings',               icon: '⚙', adminOnly: true, dividerBefore: true },
]

export default function Layout({ children, chromeless = false }: { children: ReactNode; chromeless?: boolean }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [unacked, setUnacked] = useState<number>(0)
  const [showChangePw, setShowChangePw] = useState(false)

  useEffect(() => {
    // Chromeless embeds (pkthub iframe) don't render the sidebar badge this
    // polling feeds — skip the network chatter, but keep the hook itself
    // running every render so hook order stays stable.
    if (chromeless) return

    const tick = async () => {
      try {
        const events = await api.getAlertEvents({ active: true, acked: false, limit: 500 })
        setUnacked(events.length)
      } catch {
        // silently ignore — badge just won't show if API is down
      }
    }
    tick()
    const id = setInterval(tick, 30_000)
    return () => clearInterval(id)
  }, [chromeless])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  if (chromeless) {
    return (
      <div className="bg-gray-950 text-white min-h-screen p-5">
        {children}
        {showChangePw && <ChangePasswordModal onClose={() => setShowChangePw(false)} />}
      </div>
    )
  }

  return (
    <div className="flex h-screen bg-gray-950 text-white overflow-hidden">
      <aside className="w-52 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="flex items-center px-3 py-3 border-b border-gray-800">
          <img src="lockup-64h.png" alt="pktCert" className="w-full h-auto" />
        </div>

        <nav className="flex-1 px-2 py-4 space-y-0.5">
          {NAV.filter(n => !n.adminOnly || user?.role === 'admin').map(({ to, label, icon, dividerBefore }) => (
            <div key={to}>
              {dividerBefore && <div className="h-0.5 bg-gray-600 mx-1 my-2 rounded-full" />}
              <NavLink
                to={to}
                end={to === '/'}
                className={({ isActive }) => clsx(
                  'flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors',
                  isActive
                    ? 'bg-sky-600/20 text-sky-300 font-medium'
                    : 'text-white hover:text-white hover:bg-gray-800',
                )}
              >
                <span className="text-base leading-none">{icon}</span>
                <span>{label}</span>
                {label === 'Alerts' && unacked > 0 && (
                  <span className="ml-auto bg-red-500 text-white text-xs font-bold rounded-full px-1.5 py-0.5 leading-none">
                    {unacked}
                  </span>
                )}
              </NavLink>
            </div>
          ))}
        </nav>

        <div className="px-2 pt-2">
          <NavLink
            to="/documentation"
            className={({ isActive }) => clsx(
              'flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors',
              isActive
                ? 'bg-blue-600/20 text-blue-300 font-medium'
                : 'text-white hover:text-white hover:bg-gray-800',
            )}
          >
            <span className="text-base leading-none">❐</span>
            <span>Documentation</span>
          </NavLink>
        </div>

        <div className="px-3 py-3 border-t border-gray-800">
          <div className="flex items-center gap-2 px-2 py-1.5">
            <div className="w-6 h-6 rounded-full bg-sky-600 flex items-center justify-center text-xs font-bold">
              {user?.username?.[0]?.toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-white truncate">{user?.username}</p>
              <p className="text-xs text-white capitalize">{user?.role}</p>
            </div>
            {user?.authProvider === 'local' && (
              <button onClick={() => setShowChangePw(true)} title="Change password" className="text-white hover:text-white">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/>
                </svg>
              </button>
            )}
            <button onClick={handleLogout} title="Sign out" className="text-white hover:text-white">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-12 flex-shrink-0 bg-gray-900 border-b border-gray-800 flex items-center px-5 gap-4">
          <div className="flex items-center gap-1.5 text-sm">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
            <span className="text-white text-xs">Certificate Management</span>
          </div>
        </header>

        <main className="flex-1 overflow-auto p-5">
          {children}
        </main>
      </div>

      <AiAssistant />
      {showChangePw && <ChangePasswordModal onClose={() => setShowChangePw(false)} />}
    </div>
  )
}
