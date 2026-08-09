import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { api, setToken, clearToken } from '../api/client'

interface AuthState {
  user: { username: string; role: string; hasPassword: boolean; authProvider: string } | null
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  isLoading: boolean
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthState['user']>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const runNormalAuthFlow = () => {
      const getCookie = (name: string) => {
        const match = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith(name + '='))
        return match ? decodeURIComponent(match.slice(name.length + 1)) : null
      }
      const clearCookie = (name: string) => { document.cookie = `${name}=; max-age=0; path=/` }

      const ssoToken = getCookie('sso_access_token')
      const ssoRole = getCookie('sso_role')

      if (ssoToken && ssoRole) {
        clearCookie('sso_access_token')
        clearCookie('sso_role')
        setToken(ssoToken, ssoRole)
        api.getMe()
          .then(me => setUser({ username: me.username, role: me.role, hasPassword: me.has_password, authProvider: me.auth_provider }))
          .catch(() => {})
          .finally(() => setIsLoading(false))
        return
      }

      fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' })
        .then(r => r.ok ? r.json() : null)
        .then(async data => {
          if (!data) {
            // No session yet — if every auth method is disabled, log straight
            // in as the default admin instead of showing the login form.
            const config = await api.getAuthConfig().catch(() => null)
            if (config && !config.local_enabled && !config.saml_enabled) {
              data = await api.autoLogin().catch(() => null)
            }
          }
          if (data) {
            setToken(data.access_token, data.role)
            return api.getMe()
          }
        })
        .then(me => { if (me) setUser({ username: me.username, role: me.role, hasPassword: me.has_password, authProvider: me.auth_provider }) })
        .catch(() => {})
        .finally(() => setIsLoading(false))
    }

    // When loaded through pkthub's proxy, requests carry an X-Suite-Token
    // header attached server-side by pkthub — the browser has no normal
    // cookie/JWT session in this fresh iframe context. Check for that first;
    // if it's not a suite-token context, whoami 401s and we fall through to
    // the normal cookie/JWT/SSO flow above.
    fetch('/api/suite/whoami')
      .then(r => r.ok ? r.json() : null)
      .then(whoami => {
        if (whoami?.authenticated && whoami?.via_suite_token) {
          setUser({ username: 'pktHub', role: whoami.role, hasPassword: false, authProvider: 'suite' })
          setIsLoading(false)
          return true
        }
        return false
      })
      .catch(() => false)
      .then(handled => { if (!handled) runNormalAuthFlow() })
  }, [])

  const login = async (username: string, password: string) => {
    const data = await api.login(username, password)
    setToken(data.access_token, data.role)
    const me = await api.getMe()
    setUser({ username: me.username, role: me.role, hasPassword: me.has_password, authProvider: me.auth_provider })
  }

  const logout = async () => {
    await api.logout().catch(() => {})
    clearToken()
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, login, logout, isLoading }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
