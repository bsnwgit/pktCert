/**
 * pktCert API client — typed fetch wrappers.
 * Access token is stored in memory (not localStorage).
 */

let _accessToken: string | null = null
let _tokenRole: string | null = null

export function setToken(token: string, role: string) {
  _accessToken = token
  _tokenRole = role
}

export function clearToken() {
  _accessToken = null
  _tokenRole = null
}

export function getRole(): string | null {
  return _tokenRole
}

/**
 * Build a query string, omitting undefined/null values entirely.
 * `new URLSearchParams({foo: undefined})` does NOT omit `foo` — it
 * stringifies to the literal text "undefined", which a typed backend
 * query param (e.g. `ca_id: int | None`) then fails to parse (422),
 * or a string param matches against literally, silently returning zero
 * rows instead of "no filter applied". Every optional-params GET must
 * build its query string through this helper, not the bare
 * `new URLSearchParams(params)` object-constructor form.
 */
function toQueryString(params?: Record<string, unknown>): string {
  if (!params) return ''
  const q = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) q.set(key, String(value))
  }
  const s = q.toString()
  return s ? `?${s}` : ''
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`

  const res = await fetch(`/api${path}`, { ...options, headers })

  if (res.status === 401) {
    const refreshed = await tryRefresh()
    if (refreshed) {
      headers['Authorization'] = `Bearer ${_accessToken}`
      const retry = await fetch(`/api${path}`, { ...options, headers })
      if (!retry.ok) throw new Error(`${retry.status} ${retry.statusText}`)
      return retry.status === 204 ? (null as T) : retry.json()
    }
    clearToken()
    window.location.href = '/login'
    throw new Error('Session expired')
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || res.statusText)
  }

  if (res.status === 204) return null as T
  return res.json()
}

async function tryRefresh(): Promise<boolean> {
  try {
    const res = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' })
    if (!res.ok) return false
    const data = await res.json()
    setToken(data.access_token, data.role)
    return true
  } catch {
    return false
  }
}

export const api = {
  // -- Auth --------------------------------------------------------------------
  // Deliberately bypasses request() — a bad password here is a normal login
  // failure, not an expired session, and must not trigger the 401 handler's
  // refresh-then-redirect-to-/login flow (that would hard-reload the login
  // page itself before the error message is even visible).
  login: async (username: string, password: string) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json() as Promise<{ access_token: string; role: string }>
  },
  // Deliberately bypasses request() for the same reason as login() above.
  autoLogin: async () => {
    const res = await fetch('/api/auth/auto-login', { method: 'POST' })
    if (!res.ok) throw new Error('Auto-login not available')
    return res.json() as Promise<{ access_token: string; role: string }>
  },
  logout: () => request('/auth/logout', { method: 'POST' }),
  getAuthConfig: () => request<{ saml_enabled: boolean; local_enabled: boolean }>('/auth/config'),

  // -- Users ---------------------------------------------------------------------
  getMe: () => request<User>('/users/me'),
  getUsers: () => request<User[]>('/users'),
  createUser: (body: UserIn) =>
    request<User>('/users', { method: 'POST', body: JSON.stringify(body) }),
  updateUser: (id: number, body: Partial<UserIn> & { is_active?: boolean }) =>
    request<User>(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteUser: (id: number) => request(`/users/${id}`, { method: 'DELETE' }),
  setDefaultAdmin: (id: number) => request(`/users/${id}/set-default-admin`, { method: 'PATCH' }),
  resetUserPassword: (id: number, newPassword: string) =>
    request(`/users/${id}/reset-password`, { method: 'PATCH', body: JSON.stringify({ new_password: newPassword }) }),
  changeMyPassword: (current_password: string, new_password: string) =>
    request('/users/me/change-password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }),

  // -- Dashboard --------------------------------------------------------------------
  getDashboardSummary: () => request<DashboardSummary>('/dashboard/summary'),

  // -- Certificates ---------------------------------------------------------------
  getCertificates: (params?: { status?: string; source?: string; ca_id?: number; search?: string; limit?: number }) =>
    request<Certificate[]>(`/certificates${toQueryString(params)}`),
  getCertificate: (id: number) => request<Certificate>(`/certificates/${id}`),
  // Step-up re-auth, same as revealCertificateSecret: every download, even of
  // the public cert/chain PEM, requires the current password again — no
  // client-side caching, and every call is audit-logged server-side.
  downloadCertificate: (id: number, fmt: 'pem' | 'chain', password: string) =>
    request<{ pem: string }>(`/certificates/${id}/download`, {
      method: 'POST', body: JSON.stringify({ fmt, password }),
    }),
  // Returns a certificate normally, or {pending_approval, request_id} when
  // separation of duties is enabled — the issuance then happens on approval.
  issueCertificate: (body: { common_name: string; sans: string[]; ca_id: number; template_id: number; key_passphrase?: string; auto_renew?: boolean; auto_renew_days?: number; justification?: string }) =>
    request<Certificate & { private_key_pem?: string; pending_approval?: boolean; request_id?: number; detail?: string }>('/certificates/issue', { method: 'POST', body: JSON.stringify(body) }),
  signCsr: (body: { csr_pem: string; ca_id: number; template_id: number }) =>
    request<Certificate>('/certificates/csr', { method: 'POST', body: JSON.stringify(body) }),
  renewCertificate: (id: number, body: { key_passphrase?: string } = {}) =>
    request<Certificate & { private_key_pem?: string }>(`/certificates/${id}/renew`, { method: 'POST', body: JSON.stringify(body) }),
  setAutoRenew: (id: number, auto_renew: boolean, auto_renew_days = 30) =>
    request<Certificate>(`/certificates/${id}/auto-renew`, {
      method: 'PATCH', body: JSON.stringify({ auto_renew, auto_renew_days }),
    }),
  revokeCertificate: (id: number, reason: string, reason_code = 'unspecified') =>
    request<{ status?: string; reason_code?: string; pending_approval?: boolean; request_id?: number; detail?: string }>(`/certificates/${id}/revoke`, {
      method: 'POST', body: JSON.stringify({ reason, reason_code }),
    }),
  // Step-up re-auth: current password required to decrypt a stored private
  // key or install passcode. Every successful call is audit-logged server-side.
  revealCertificateSecret: (id: number, field: 'key' | 'passcode', password: string) =>
    request<{ key?: string; passcode?: string }>(`/certificates/${id}/reveal-secret`, {
      method: 'POST', body: JSON.stringify({ field, password }),
    }),
  uploadExternalCertificate: async (opts: { certFile: File; keyFile?: File; passphrase?: string; passcode?: string }): Promise<Certificate> => {
    const formData = new FormData()
    formData.append('cert_file', opts.certFile)
    if (opts.keyFile) formData.append('key_file', opts.keyFile)
    if (opts.passphrase) formData.append('passphrase', opts.passphrase)
    if (opts.passcode) formData.append('passcode', opts.passcode)
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    const res = await fetch('/api/certificates/upload', { method: 'POST', headers, body: formData })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json()
  },

  // -- Certificate Authorities --------------------------------------------------------
  getCas: () => request<CertificateAuthority[]>('/cas'),
  getCa: (id: number) => request<CertificateAuthority>(`/cas/${id}`),
  generateCa: (body: {
    name: string; ca_type: string; parent_ca_id?: number | null
    key_algorithm: string; key_size: number; validity_days: number
    path_length?: number | null
    permitted_dns?: string[]; excluded_dns?: string[]
    permitted_ip?: string[]; excluded_ip?: string[]
  }) =>
    request<CertificateAuthority>('/cas/generate', { method: 'POST', body: JSON.stringify(body) }),
  importCa: (body: { name: string; cert_pem: string; private_key_pem: string; ca_type: string; parent_ca_id?: number | null; key_passphrase?: string }) =>
    request<CertificateAuthority>('/cas/import', { method: 'POST', body: JSON.stringify(body) }),
  // Offline root workflow — the root's private key never enters pktCert.
  importRootCert: (body: { name: string; cert_pem: string }) =>
    request<CertificateAuthority>('/cas/import-root-cert', { method: 'POST', body: JSON.stringify(body) }),
  requestIntermediate: (body: {
    name: string; parent_ca_id: number; key_algorithm: string; key_size: number
    path_length?: number | null
    permitted_dns?: string[]; excluded_dns?: string[]; permitted_ip?: string[]; excluded_ip?: string[]
  }) =>
    request<CertificateAuthority & { csr_pem: string }>('/cas/request-intermediate', { method: 'POST', body: JSON.stringify(body) }),
  getCaCsr: (id: number) =>
    request<{ name: string; csr_pem: string; status: string }>(`/cas/${id}/csr`),
  importSignedCert: (id: number, cert_pem: string) =>
    request<CertificateAuthority>(`/cas/${id}/import-signed-cert`, { method: 'POST', body: JSON.stringify({ cert_pem }) }),
  uploadCrl: (id: number, crl_pem: string) =>
    request<{ status: string; this_update: string; next_update: string | null; revoked_count: number }>(
      `/cas/${id}/upload-crl`, { method: 'POST', body: JSON.stringify({ crl_pem }) }),

  setCaStatus: (id: number, status: 'active' | 'disabled') =>
    request<CertificateAuthority>(`/cas/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  deleteCa: (id: number) => request(`/cas/${id}`, { method: 'DELETE' }),
  getCrl: (id: number) =>
    request<{ crl_pem: string; crl_number: number; this_update: string; next_update: string }>(`/cas/${id}/crl`),

  // -- Approvals (separation of duties; disabled by default) ------------------------
  getApprovalConfig: () =>
    request<{ issuance_approval_required: boolean; revocation_approval_required: boolean; admin_count: number; pending_count: number }>('/approvals/config'),
  getApprovals: (params?: { status?: string; limit?: number }) =>
    request<CertRequest[]>(`/approvals${toQueryString(params)}`),
  approveRequest: (id: number, note = '') =>
    request<CertRequest & { certificate_id?: number }>(`/approvals/${id}/approve`, { method: 'POST', body: JSON.stringify({ note }) }),
  rejectRequest: (id: number, note = '') =>
    request<CertRequest>(`/approvals/${id}/reject`, { method: 'POST', body: JSON.stringify({ note }) }),
  cancelRequest: (id: number) =>
    request<CertRequest>(`/approvals/${id}/cancel`, { method: 'POST' }),

  // -- Enrolment profiles (EST / SCEP device enrolment) ------------------------------
  getEnrollmentProfiles: () => request<EnrollmentProfile[]>('/enrollment-profiles'),
  createEnrollmentProfile: (body: {
    name: string; protocol: 'est' | 'scep'; ca_id: number; template_id: number
    username?: string; allowed_name_suffix?: string; max_certs?: number | null; enabled?: boolean
  }) => request<EnrollmentProfile & { secret: string }>('/enrollment-profiles', { method: 'POST', body: JSON.stringify(body) }),
  updateEnrollmentProfile: (id: number, body: {
    name: string; protocol: 'est' | 'scep'; ca_id: number; template_id: number
    username?: string; allowed_name_suffix?: string; max_certs?: number | null; enabled?: boolean
  }) => request<EnrollmentProfile>(`/enrollment-profiles/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  rotateEnrollmentSecret: (id: number) =>
    request<{ secret: string }>(`/enrollment-profiles/${id}/rotate-secret`, { method: 'POST' }),
  deleteEnrollmentProfile: (id: number) => request(`/enrollment-profiles/${id}`, { method: 'DELETE' }),
  getEnrollmentLog: (params?: { outcome?: string; limit?: number }) =>
    request<EnrollmentLogEntry[]>(`/enrollment-profiles/log${toQueryString(params)}`),

  // -- Templates ---------------------------------------------------------------------
  getTemplates: () => request<CertTemplate[]>('/templates'),
  createTemplate: (body: Partial<CertTemplate>) => request<CertTemplate>('/templates', { method: 'POST', body: JSON.stringify(body) }),
  updateTemplate: (id: number, body: Partial<CertTemplate>) => request<CertTemplate>(`/templates/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteTemplate: (id: number) => request(`/templates/${id}`, { method: 'DELETE' }),

  // -- Scan targets ---------------------------------------------------------------------
  getScanTargets: () => request<ScanTarget[]>('/scan-targets'),
  createScanTarget: (body: Partial<ScanTarget>) => request<ScanTarget>('/scan-targets', { method: 'POST', body: JSON.stringify(body) }),
  updateScanTarget: (id: number, body: Partial<ScanTarget>) => request<ScanTarget>(`/scan-targets/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteScanTarget: (id: number) => request(`/scan-targets/${id}`, { method: 'DELETE' }),
  scanTargetNow: (id: number) => request<{ status: string; certificates_found: number; hosts_scanned: number; errors: number }>(`/scan-targets/${id}/scan-now`, { method: 'POST' }),

  // -- Alerts ---------------------------------------------------------------------
  getAlertRules: () => request<AlertRule[]>('/alerts/rules'),
  createAlertRule: (body: Partial<AlertRule>) => request<AlertRule>('/alerts/rules', { method: 'POST', body: JSON.stringify(body) }),
  updateAlertRule: (id: number, body: Partial<AlertRule>) => request<AlertRule>(`/alerts/rules/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteAlertRule: (id: number) => request(`/alerts/rules/${id}`, { method: 'DELETE' }),
  toggleAlertRule: (id: number) => request<AlertRule>(`/alerts/rules/${id}/toggle`, { method: 'POST' }),
  exportAlertRules: async (): Promise<Blob> => {
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    const res = await fetch('/api/alerts/rules/export', { headers })
    if (!res.ok) throw new Error(`Export failed: ${res.status} ${res.statusText}`)
    return res.blob()
  },
  importAlertRulesCsv: async (file: File): Promise<{ created: number; skipped: number; errors: string[] }> => {
    const formData = new FormData()
    formData.append('file', file)
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    const res = await fetch('/api/alerts/rules/import-csv', { method: 'POST', headers, body: formData })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json()
  },
  getAlertEvents: (params?: { active?: boolean; acked?: boolean; since?: string | null; until?: string | null; limit?: number }) =>
    request<AlertEvent[]>(`/alerts/events${toQueryString(params)}`),
  ackAlertEvent: (id: number) => request(`/alerts/events/${id}/ack`, { method: 'POST' }),
  ackAllAlertEvents: () => request<{ status: string; acked: number }>('/alerts/events/ack-all', { method: 'POST' }),
  resolveAlertEvent: (id: number) => request(`/alerts/events/${id}/resolve`, { method: 'POST' }),

  // -- Logs ---------------------------------------------------------------------
  getAppLogs: (params?: { level?: string; logger?: string; search?: string; since?: string | null; until?: string | null; limit?: number; offset?: number }) =>
    request<{ total: number; limit: number; offset: number; records: AppLog[] }>(`/logs${toQueryString(params)}`),
  getLogStats: () => request<LogStats>('/logs/stats'),
  clearLogs: () => request<{ status: string }>('/logs', { method: 'DELETE' }),
  setLogCaptureLevel: (level: string) => request<{ capture_level: string }>(`/logs/level?level=${level}`, { method: 'POST' }),

  // -- Suite (inbound — pktHub registering this app) --------------------------------
  getSuiteToken: () => request<{ suite_token: string; has_token: boolean }>('/suite/token'),
  regenerateSuiteToken: () => request<{ suite_token: string; status: string }>('/suite/regenerate', { method: 'POST' }),

  // -- Integrations (outbound — pktCert calling into sibling pkt apps) --------------
  getIntegrations: () => request<Integration[]>('/integrations'),
  createIntegration: (body: IntegrationInput) =>
    request<Integration>('/integrations', { method: 'POST', body: JSON.stringify(body) }),
  updateIntegration: (id: number, body: Partial<IntegrationInput>) =>
    request<Integration>(`/integrations/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
  deleteIntegration: (id: number) => request(`/integrations/${id}`, { method: 'DELETE' }),
  testIntegration: (id: number) => request<{ healthy: boolean; detail: string }>(`/integrations/${id}/test`, { method: 'POST' }),

  // -- IP Info / Reputation Lookup ---------------------------------------------------
  getIpInfo: (ip: string) => request<Record<string, unknown>>(`/ip-info/${encodeURIComponent(ip)}`),
  getInternalIpInfo: (ip: string) => request<Record<string, unknown>>(`/ip-info/internal/${encodeURIComponent(ip)}`),

  // -- AI / Settings ---------------------------------------------------------------------
  aiChat: (question: string, context: Record<string, unknown> = {}) =>
    request<{ answer: string; provider?: string; tokens_used: number }>('/ai/chat', { method: 'POST', body: JSON.stringify({ question, context }) }),

  getSettings: () => request<Record<string, unknown>>('/settings'),
  updateSettings: (values: Record<string, unknown>) => request('/settings', { method: 'PUT', body: JSON.stringify({ values }) }),
  testNotification: (channel: string) =>
    request<{ status: string; detail?: string }>('/settings/test-notification', {
      method: 'POST',
      body: JSON.stringify({ channel }),
    }),

  // -- System ---------------------------------------------------------------------
  getSystemInfo: () =>
    request<{
      app_name: string; version: string; install_dir: string
      github: string; license: string; developer: string; contact: string
    }>('/system/info'),
  listBackups: () => request<Array<{ name: string; path: string; size_bytes: number; files: string[] }>>('/system/backups'),
  runBackupNow: () => request<{ status: string; path: string; files: string[]; kept: number }>('/system/backups/run', { method: 'POST' }),
  restartService: () => request<{ status: string; message: string }>('/system/restart', { method: 'POST' }),
  getPort: () => request<{ port: number }>('/system/port'),
  setPort: (port: number) =>
    request<{ port: number; message: string }>('/system/port', {
      method: 'POST',
      body: JSON.stringify({ port }),
    }),

  // ── Storage (SQLite-only — no backend picker like pktsnmp/pktflow) ─────────
  getStorageStats: () => request<StorageStats>('/system/storage-stats'),
  runCleanupNow: () => request<CleanupResult>('/system/cleanup', { method: 'POST' }),

  // ── Full backup bundle export/import ────────────────────────────────────
  exportConfig: async (password: string): Promise<Blob> => {
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    // FastAPI needs this to parse the JSON body carrying the password.
    headers['Content-Type'] = 'application/json'
    const res = await fetch('/api/system/export', {
      method: 'POST',
      headers,
      body: JSON.stringify({ password }),
    })
    if (!res.ok) throw new Error(`Export failed: ${res.status} ${res.statusText}`)
    return res.blob()
  },
  importBundle: async (file: File, files?: string[]): Promise<Record<string, string>> => {
    const formData = new FormData()
    formData.append('file', file)
    if (files) formData.append('files', files.join(','))
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    const res = await fetch('/api/system/import', { method: 'POST', headers, body: formData })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json()
  },
  restoreSnapshot: (name: string, files?: string[]): Promise<Record<string, string>> => {
    const qs = files && files.length ? `?files=${encodeURIComponent(files.join(','))}` : ''
    return request<Record<string, string>>(`/system/backups/restore/${encodeURIComponent(name)}${qs}`, { method: 'POST' })
  },

  // ── Documentation ─────────────────────────────────────────────────────────
  getDocs: () => request<{ slug: string; title: string }[]>('/docs-content'),
  getDoc: (slug: string) =>
    request<{ slug: string; title: string; content: string }>(`/docs-content/${slug}`),

  // ── SSL ───────────────────────────────────────────────────────────────────
  getSslStatus: () => request<SslStatus>('/system/ssl/status'),
  uploadSsl: async (cert: File, key: File): Promise<SslStatus> => {
    const formData = new FormData()
    formData.append('cert', cert)
    formData.append('key', key)
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    const res = await fetch('/api/system/ssl/upload', { method: 'POST', headers, body: formData })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json()
  },
  deleteSsl: () => request<SslStatus>('/system/ssl/cert', { method: 'DELETE' }),
  uploadSslPfx: async (pfx: File, passphrase: string): Promise<SslStatus> => {
    const formData = new FormData()
    formData.append('pfx', pfx)
    formData.append('passphrase', passphrase)
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    const res = await fetch('/api/system/ssl/upload-pfx', { method: 'POST', headers, body: formData })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json()
  },

  // ── User API Keys (suite-wide IP Lookup providers + Censys) ─────────────────
  getUserApiKeys: () => request<UserApiKey[]>('/user-api-keys'),
  setUserApiKey: (provider: string, api_key: string) =>
    request<UserApiKey>(`/user-api-keys/${provider}`, { method: 'PUT', body: JSON.stringify({ api_key }) }),
  testUserApiKey: (provider: string, api_key: string) =>
    request<{ status: string; detail: string }>(`/user-api-keys/${provider}/test`, { method: 'POST', body: JSON.stringify({ api_key }) }),
  setIpinfoFields: (enabled_fields: string[]) =>
    request<UserApiKey>('/user-api-keys/ipinfo/fields', { method: 'PUT', body: JSON.stringify({ enabled_fields }) }),
  setIpapiIsFields: (enabled_fields: string[]) =>
    request<UserApiKey>('/user-api-keys/ipapi_is/fields', { method: 'PUT', body: JSON.stringify({ enabled_fields }) }),
  setIpapiIsFreeTier: (free_tier: boolean) =>
    request<UserApiKey>('/user-api-keys/ipapi_is/free-tier', { method: 'PUT', body: JSON.stringify({ free_tier }) }),
  setMxtoolboxFields: (enabled_fields: string[]) =>
    request<UserApiKey>('/user-api-keys/mxtoolbox/fields', { method: 'PUT', body: JSON.stringify({ enabled_fields }) }),
  setProviderEnabled: (provider: string, enabled: boolean) =>
    request<UserApiKey>(`/user-api-keys/${provider}/enabled`, { method: 'PUT', body: JSON.stringify({ enabled }) }),
}

export interface Integration {
  id: number
  name: string
  app_name: string
  base_url: string
  has_token: boolean
  enabled: boolean
  verify_tls: boolean
  health_status: string
  last_health_check: string | null
}

export interface IntegrationInput {
  name: string
  app_name?: string
  base_url: string
  suite_token: string
  enabled?: boolean
  verify_tls?: boolean
}

export interface UserApiKey {
  provider: string
  label: string
  api_key: string
  updated_at: string | null
  enabled_fields: string[] | null // ipinfo/ipapi_is/mxtoolbox only; null = not customized (all shown)
  free_tier: boolean // ipapi_is only — use its keyless free tier instead of api_key
  enabled: boolean // modal-section providers only — show this provider's section in the IP Lookup modal at all
}

export interface StorageStats {
  db_size_bytes: number
  row_counts: Record<string, number>
}

export interface CleanupResult {
  status: string
  removed_alert_events: number
}

export interface SslStatus {
  installed: boolean
  expires?: string
  expires_iso?: string
  days_until_expiry?: number
  subject?: string
  issuer?: string
  error?: string
  status?: string
}

// -- Types -----------------------------------------------------------------------

export interface UserIn {
  username: string
  email: string
  password?: string
  role: string
}

export interface User {
  id: number
  username: string
  email: string
  role: string
  is_active: boolean
  is_default_admin: boolean
  auth_provider: string
  created_at: string
  last_login: string | null
  has_password: boolean
}

export type CertStatus = 'valid' | 'expiring' | 'expired' | 'revoked' | 'superseded' | 'unknown'
export type CertSource = 'scan' | 'ct' | 'issued' | 'external'

export interface Certificate {
  id: number
  common_name: string
  san: string[]
  issuer: string
  subject: string
  serial_number: string
  fingerprint_sha256: string
  not_before: string | null
  not_after: string | null
  key_algorithm: string | null
  key_size: number | null
  signature_algorithm: string | null
  status: CertStatus
  source: CertSource
  scan_target_id: number | null
  host: string | null
  port: number | null
  ca_id: number | null
  template_id: number | null
  has_private_key: boolean
  has_passcode: boolean
  key_encrypted: boolean
  first_seen_at: string
  last_seen_at: string
  revoked_at: string | null
  revoked_reason: string | null
  revoked_reason_code: string | null
  created_at: string
  renewed_from_id: number | null
  renewed_to_id: number | null
  auto_renew: boolean
  auto_renew_days: number
  private_key_pem?: string
}

export interface CertRequest {
  id: number
  request_type: 'issue' | 'revoke'
  status: 'pending' | 'approved' | 'rejected' | 'cancelled'
  common_name: string | null
  sans: string[]
  ca_id: number | null
  template_id: number | null
  auto_renew: boolean
  auto_renew_days: number
  certificate_id: number | null
  reason: string | null
  reason_code: string | null
  requested_by: string
  requested_by_id: number | null
  justification: string | null
  requested_at: string
  decided_by: string | null
  decided_at: string | null
  decision_note: string | null
  resulting_certificate_id: number | null
}

export interface EnrollmentProfile {
  id: number
  name: string
  protocol: 'est' | 'scep'
  ca_id: number
  template_id: number
  username: string | null
  enabled: boolean
  allowed_name_suffix: string | null
  max_certs: number | null
  issued_count: number
  created_at: string
  last_used_at: string | null
}

export interface EnrollmentLogEntry {
  id: number
  profile_id: number | null
  protocol: string
  operation: string
  client_ip: string | null
  subject: string | null
  outcome: 'issued' | 'denied' | 'error'
  detail: string | null
  certificate_id: number | null
  created_at: string
}

export type CaType = 'root' | 'intermediate'

export interface CertificateAuthority {
  id: number
  name: string
  ca_type: CaType
  parent_ca_id: number | null
  subject: string
  cert_pem: string
  key_algorithm: string
  key_size: number
  signature_algorithm: string
  not_before: string
  not_after: string
  status: 'active' | 'disabled' | 'expired' | 'revoked' | 'pending_signature'
  crl_number: number
  path_length: number | null
  key_storage: 'local' | 'offline'
  has_csr: boolean
  has_uploaded_crl: boolean
  name_constraints: {
    permitted_dns: string[]; excluded_dns: string[]
    permitted_ip: string[]; excluded_ip: string[]
  } | null
  source: 'generated' | 'imported'
  created_at: string
}

export interface CertTemplate {
  id: number
  name: string
  key_algorithm: string
  key_size: number
  validity_days: number
  key_usage: string[]
  extended_key_usage: string[]
  default_ca_id: number | null
  created_at: string
}

export interface ScanTarget {
  id: number
  name: string
  host: string | null
  cidr: string | null
  ports: string
  schedule_minutes: number
  enabled: boolean
  last_scan_at: string | null
  last_status: 'ok' | 'error' | 'unknown'
  last_error: string | null
  created_at: string
}

export interface DashboardSummary {
  total: number
  valid: number
  expiring: number
  expired: number
  revoked: number
  issued: number
  scanned: number
  ca_count: number
  scan_targets: number
  active_alerts: number
  expiring_soon: Array<{ id: number; common_name: string; not_after: string; status: string }>
  by_ca: Record<string, number>
}

export type AlertConditionType = 'cert_expiring' | 'cert_expired' | 'cert_revoked' | 'ca_expiring' | 'scan_target_unreachable'

export interface AlertRule {
  id: number
  name: string
  condition_type: AlertConditionType
  threshold: number | null
  severity: 'info' | 'warning' | 'critical'
  enabled: boolean
  cooldown_min: number
  channels: string[]
  created_at: string
}

export interface AlertEvent {
  id: number
  rule_id: number | null
  certificate_id: number | null
  ca_id: number | null
  severity: string
  message: string
  value: number | null
  threshold: number | null
  active: boolean
  acked: boolean
  acked_by: string | null
  acked_at: string | null
  resolved: boolean
  auto_resolved: boolean
  resolved_at: string | null
  created_at: string
}

export interface AppLog {
  id: number
  level: string
  logger: string
  message: string
  exc_info: string | null
  created_at: string
}

export interface LogStats {
  total: number
  by_level: Record<string, number>
  loggers: string[]
  latest_ts: string | null
  capture_level: string
}
