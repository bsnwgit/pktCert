import { ReactNode, useState, useEffect } from 'react'
import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../store/auth'
import { api, getToken } from '../api/client'
import ResonanceMount from '../resonance/ResonanceMount'
import clsx from 'clsx'
import { BrandLockup } from './Brand'

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

// pktHub mirrors this menu in its own APPS sidebar, reading it from
// app/api/nav.py's NAV_MANIFEST. Add or rename an entry here and it belongs
// there too, or the hub keeps offering the old one. The approvalsOnly
// condition below is applied server-side there as well.
const NAV = [
  { to: '/',                        label: 'Dashboard',              icon: '◑', adminOnly: false },
  { to: '/scan-targets',            label: 'Scan Targets',           icon: '⌕', adminOnly: false },
  { to: '/certificates',            label: 'Certificates',           icon: '▤', adminOnly: false, dividerBefore: true },
  { to: '/certificate-authorities', label: 'Certificate Authorities', icon: '⛨', adminOnly: false },
  // Hidden unless separation of duties is switched on — see approvalsVisible
  // below. A queue nobody uses is just a dead link in the sidebar.
  { to: '/approvals',               label: 'Approvals',              icon: '✓', adminOnly: false, approvalsOnly: true },
  { to: '/alerts',                  label: 'Alerts',                 icon: '△', adminOnly: false, dividerBefore: true },
  { to: '/logs',                    label: 'Logs',                   icon: '☰', adminOnly: false },
  { to: '/settings',                label: 'Settings',               icon: '⚙', adminOnly: true, dividerBefore: true },
]

export default function Layout({ children, chromeless = false }: { children: ReactNode; chromeless?: boolean }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [unacked, setUnacked] = useState<number>(0)
  const [approvalsVisible, setApprovalsVisible] = useState(false)
  const [showChangePw, setShowChangePw] = useState(false)
  const [navOpen, setNavOpen] = useState(false)
  const { pathname } = useLocation()

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
    // Show Approvals only when it's actually in use. Pending requests keep it
    // visible even after the setting is turned back off, so anything already
    // raised can still be actioned rather than being stranded behind a hidden
    // page.
    const checkApprovals = async () => {
      try {
        const cfg = await api.getApprovalConfig()
        setApprovalsVisible(
          cfg.issuance_approval_required || cfg.revocation_approval_required || cfg.pending_count > 0,
        )
      } catch {
        setApprovalsVisible(false)
      }
    }

    tick()
    checkApprovals()
    const id = setInterval(() => { tick(); checkApprovals() }, 30_000)
    return () => clearInterval(id)
  }, [chromeless])

  // A NavLink does not unmount this component, so without this the drawer
  // stays open on top of the page it has just navigated to.
  useEffect(() => { setNavOpen(false) }, [pathname])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  // Definite height, not min-height: a page that fills its container sizes
  // itself with h-full, which collapses to zero against an auto-height parent.
  // This mirrors <main> below, so dropping the chrome changes what is on
  // screen and not how the page lays out.
  if (chromeless) {
    return (
      <div className="relative z-10 text-white h-dvh overflow-auto p-6">
        {children}
        {showChangePw && <ChangePasswordModal onClose={() => setShowChangePw(false)} />}
      </div>
    )
  }

  return (
    <div className="relative z-10 flex h-dvh text-white overflow-hidden">
      {navOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
          onClick={() => setNavOpen(false)}
          aria-hidden
        />
      )}

      <aside
        className={clsx(
          'f-drawer w-[min(82vw,320px)] md:w-[210px] flex-shrink-0 border-r border-gray-800 flex flex-col',
          // Off-canvas overlay on a phone, the desk sidebar from md up. The
          // md: resets are what keep the desktop rendering unchanged.
          //
          // Width tracks the viewport instead of sitting at a fixed 260: 82vw
          // is 262px on a 320px SE and caps at 320px from roughly 390px up, so
          // it stays proportional on the small phones where a fixed width hurts
          // and stops sprawling on the wide ones. The cap also guarantees a
          // strip of backdrop stays visible, which is what makes the panel read
          // as something you can dismiss rather than a new page.
          'fixed inset-y-0 left-0 z-40 transition-transform duration-200',
          'md:static md:z-auto md:translate-x-0 md:transition-none',
          navOpen ? 'translate-x-0' : '-translate-x-full',
        )}
        style={{ background: 'linear-gradient(180deg, rgba(216,180,110,.025), transparent 40%)' }}
      >
        <div className="flex items-center px-5 py-4 border-b border-gray-800">
          <BrandLockup markSize={30} />
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-4 space-y-0.5">
          {NAV.filter(n => (!n.adminOnly || user?.role === 'admin') && (!n.approvalsOnly || approvalsVisible))
            .map(({ to, label, icon, dividerBefore }) => (
            <div key={to}>
              {dividerBefore && <div className="h-px bg-blue-500/25 mx-3 my-3" />}
              <NavLink
                to={to}
                end={to === '/'}
                className={({ isActive }) => clsx(
                  'flex items-center gap-3 pl-3 pr-3 py-3.5 md:py-2.5 text-[13px] md:text-[11.5px] uppercase tracking-[0.1em] md:tracking-[0.13em] transition-colors',
                  isActive
                    ? 'bg-sky-600/20 text-sky-300 font-medium'
                    : 'text-gray-400 hover:text-white hover:bg-blue-500/[0.04] border-l-2 border-transparent',
                )}
              >
                <span className="text-xs w-3.5 text-center leading-none">{icon}</span>
                <span>{label}</span>
                {label === 'Alerts' && unacked > 0 && (
                  <span className="ml-auto font-mono text-[11px] md:text-[9.5px] text-red-500 border border-red-500/50 px-1.5 leading-relaxed">
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
              'flex items-center gap-3 pl-3 pr-3 py-3.5 md:py-2.5 text-[13px] md:text-[11.5px] uppercase tracking-[0.1em] md:tracking-[0.13em] transition-colors',
              isActive
                ? 'bg-gradient-to-r from-blue-500/[0.12] to-transparent text-blue-300 border-l-2 border-blue-500'
                : 'text-gray-400 hover:text-white hover:bg-blue-500/[0.04] border-l-2 border-transparent',
            )}
          >
            <span className="text-xs w-3.5 text-center leading-none">❐</span>
            <span>Documentation</span>
          </NavLink>
        </div>

        <div className="f-safe-b px-3 py-3 border-t border-gray-800">
          <div className="flex items-center gap-2 px-2 py-1.5">
            <div className="w-6 h-6 rounded-full bg-sky-600 flex items-center justify-center text-xs font-bold">
              {user?.username?.[0]?.toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-white truncate">{user?.username}</p>
              <p className="text-xs text-white capitalize">{user?.role}</p>
            </div>
            {user?.authProvider === 'local' && (
              <button onClick={() => setShowChangePw(true)} title="Change password" className="f-tap text-white hover:text-white">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/>
                </svg>
              </button>
            )}
            <button onClick={handleLogout} title="Sign out" className="f-tap text-white hover:text-white">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-12 flex-shrink-0 border-b border-gray-800 flex items-center px-4 md:px-6 gap-3 md:gap-5">
          {/* On the desk this bar holds a status dot and little else, so the
              drawer control and the lockup fit into it without displacing
              anything that was already there. */}
          <button
            onClick={() => setNavOpen(true)}
            aria-label="Open navigation"
            className="f-tap md:hidden -ml-2 text-white"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5M3.75 17.25h16.5" />
            </svg>
          </button>
          <div className="md:hidden">
            <BrandLockup markSize={22} />
          </div>
          <div className="flex items-center gap-1.5 text-sm ml-auto md:ml-0">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
            <span className="text-white text-xs hidden sm:inline">Certificate Management</span>
          </div>
        </header>

        <main className="flex-1 overflow-auto p-5">
          {children}
        </main>
      </div>
      {showChangePw && <ChangePasswordModal onClose={() => setShowChangePw(false)} />}
      {/* One mount for the whole authenticated app, so a route change does
          not cost a new resonance session. */}
      <ResonanceMount getToken={getToken} />
    </div>
  )
}
