import { useState, useEffect, FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../store/auth'
import { api } from '../api/client'
import { BrandLockup } from '../components/Brand'

const SSO_ERROR_MESSAGES: Record<string, string> = {
  user_inactive:          'Your account is inactive. Contact an administrator.',
  saml_disabled:          'SAML SSO is not currently enabled.',
  saml_processing_failed: 'SAML response could not be processed. Check your IdP configuration.',
  saml_invalid_response:  'SAML response validation failed. Check IdP certificate and entity IDs.',
  not_authenticated:      'SAML authentication was not confirmed by the IdP.',
}

export default function Login() {
  const { login, user } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [samlEnabled, setSamlEnabled] = useState(false)
  const [localEnabled, setLocalEnabled] = useState(true)
  const [samlLoading, setSamlLoading] = useState(false)

  // If auto-login (all auth methods disabled) already established a session
  // in the background, leave immediately instead of showing a login form.
  useEffect(() => {
    if (user) navigate('/', { replace: true })
  }, [user])

  useEffect(() => {
    const ssoError = searchParams.get('sso_error')
    if (ssoError) setError(SSO_ERROR_MESSAGES[ssoError] ?? `SSO error: ${ssoError}`)

    api.getAuthConfig()
      .then(data => {
        setSamlEnabled(!!data.saml_enabled)
        setLocalEnabled(data.local_enabled !== false)
      })
      .catch(() => {})
  }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      navigate('/')
    } catch (err: any) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const handleSamlLogin = () => {
    setSamlLoading(true)
    window.location.href = '/api/auth/saml/login'
  }

  return (
    <div className="relative z-10 min-h-screen flex items-center justify-center">
      <div className="w-full max-w-sm">
        <div className="flex justify-center mb-8">
          <BrandLockup markSize={52} />
        </div>

        <div className="f-panel f-tick-on p-8 space-y-6">
          {samlEnabled && (
            <>
              <button
                type="button"
                onClick={handleSamlLogin}
                disabled={samlLoading}
                className="w-full flex items-center justify-center gap-2.5 bg-sky-700 hover:bg-sky-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg py-2.5 transition-colors"
              >
                {samlLoading ? 'Redirecting…' : 'Sign in with SSO'}
              </button>
              {localEnabled && (
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-px bg-gray-700" />
                  <span className="text-xs text-gray-500">or</span>
                  <div className="flex-1 h-px bg-gray-700" />
                </div>
              )}
            </>
          )}

          {localEnabled && <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-white mb-1.5">Username or Email</label>
              <input
                type="text" value={username} onChange={e => setUsername(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); e.currentTarget.form?.requestSubmit() } }}
                required autoFocus
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent"
                placeholder="admin"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-white mb-1.5">Password</label>
              <input
                type="password" value={password} onChange={e => setPassword(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); e.currentTarget.form?.requestSubmit() } }}
                required
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent"
                placeholder="••••••••"
              />
            </div>

            {error && (
              <div className="bg-red-950 border border-red-800 rounded-lg px-3 py-2 text-red-300 text-sm">
                {error}
              </div>
            )}

            <button
              type="submit" disabled={loading}
              className="w-full bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg py-2.5 transition-colors"
            >
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>}
        </div>
      </div>
    </div>
  )
}
