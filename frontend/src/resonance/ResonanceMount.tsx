/**
 * Resonance embed mount — vendored, byte-identical across pkt* apps.
 *
 * Mounted once inside the authenticated layout, never per route, because every
 * mount costs a fresh single-use code and a remount throws away the running
 * conversation. It renders no markup of its own: resonance's loader draws the
 * launcher and its panel, and this component only decides whether the script
 * tag exists and with which attributes.
 *
 * Depends on nothing app-specific except the token accessor passed in, so the
 * directory can be copied between apps unchanged.
 *
 * Two failure modes are handled here because embed.js does not handle them:
 * it logs once to the console and gives up permanently, which from the user's
 * side is indistinguishable from the feature not existing.
 *
 *   - the script never loads (ad blocker, wrong address, resonance down):
 *     onerror fires, so retry with backoff and report it once we stop.
 *   - the script loads but never initialises: watch for window.Resonance and
 *     treat its absence the same way.
 *
 * A failed *renewal* is deliberately not guessed at. embed.js renews out of
 * band, through an endpoint this component cannot observe, so there is no
 * signal here that distinguishes a dead session from a quiet one — and a timer
 * that assumed the worst would destroy live conversations to fix a rare
 * failure. The server-side breaker and the load-failure counter surface what is
 * actually observable.
 */
import { useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'

const CONFIG_PATH = '/api/resonance/config'
const REPORT_PATH = '/api/resonance/report'
const CODE_PATH = '/api/resonance/code'

// Retry schedule for a script that does not arrive. Roughly two minutes in
// total, which covers an app restart during page load — the likeliest cause on
// a healthy install, since deploying restarts the service under live sessions.
const RETRY_DELAYS_MS = [2000, 5000, 15000, 30000, 60000]

// How long to wait for window.Resonance after the script reports it loaded.
const INIT_TIMEOUT_MS = 10000

// Retry schedule for the config call itself. Short and few: the only failure
// worth waiting out is the moment between the app reporting a signed-in user
// and its access token actually existing, which is over in well under a second.
const CONFIG_RETRY_DELAYS_MS = [250, 500, 1000, 2000]

// Capabilities the browser cannot deliver over plain HTTP. getUserMedia is
// gated on a secure context, so a key that grants mic would otherwise render a
// control that silently does nothing. `narrow` can only ever reduce what the
// key allows, so sending it is safe even when these were never granted.
const INSECURE_CONTEXT_NARROW = {
  parts: ['visual', 'transcript', 'input', 'mode', 'text'],
  cap: { mic: false, speak: false },
}

export interface ResonanceConfig {
  enabled: boolean
  base_url?: string
  style?: string
  target?: string
  label?: string
  side?: string
  width?: string
  height?: string
  open?: boolean
  exclude_paths?: string[]
}

interface Props {
  /** Reads the app's in-memory access token. The only app-specific dependency. */
  getToken: () => string | null
}

declare global {
  interface Window {
    Resonance?: {
      open?: () => void
      close?: () => void
      toggle?: () => void
      destroy?: () => void
      frame?: HTMLIFrameElement | null
    }
  }
}

export default function ResonanceMount({ getToken }: Props) {
  const location = useLocation()
  const scriptRef = useRef<HTMLScriptElement | null>(null)
  const attemptRef = useRef(0)
  const timerRef = useRef<number | null>(null)
  const configRef = useRef<ResonanceConfig | null>(null)
  const reportedRef = useRef(false)

  useEffect(() => {
    let cancelled = false

    const authFetch = (path: string, init: RequestInit = {}) => {
      const token = getToken()
      return fetch(path, {
        ...init,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(init.headers as Record<string, string> | undefined),
        },
      })
    }

    // Reported once per mount: a page that cannot load the widget will not load
    // it on retry either, and the count should reflect affected users, not
    // affected attempts.
    const report = (reason: string) => {
      if (reportedRef.current) return
      reportedRef.current = true
      authFetch(REPORT_PATH, { method: 'POST', body: JSON.stringify({ reason }) }).catch(() => {})
    }

    const clearTimer = () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current)
        timerRef.current = null
      }
    }

    const teardown = () => {
      clearTimer()
      try {
        window.Resonance?.destroy?.()
      } catch {
        /* destroy is best effort — the script may have failed before defining it */
      }
      scriptRef.current?.remove()
      scriptRef.current = null
    }

    /** Hide what the page cannot support. Less-only by contract, so this can
     *  never widen what the key granted. */
    const narrowForInsecureContext = (baseUrl: string) => {
      if (window.isSecureContext) return
      const frame = window.Resonance?.frame
      if (!frame?.contentWindow) return
      try {
        frame.contentWindow.postMessage({ rsn: 1, kind: 'narrow', ...INSECURE_CONTEXT_NARROW }, baseUrl)
      } catch {
        /* a rejected narrow leaves the key's own grants in place */
      }
    }

    const scheduleRetry = (cfg: ResonanceConfig) => {
      const delay = RETRY_DELAYS_MS[attemptRef.current]
      if (delay === undefined) {
        report('script_error')
        return
      }
      attemptRef.current += 1
      timerRef.current = window.setTimeout(() => {
        if (!cancelled) inject(cfg)
      }, delay)
    }

    const inject = (cfg: ResonanceConfig) => {
      const baseUrl = (cfg.base_url || '').replace(/\/+$/, '')
      if (!baseUrl) return

      scriptRef.current?.remove()

      const el = document.createElement('script')
      el.src = `${baseUrl}/embed.js`
      el.async = true
      // Relative on purpose: it must resolve to this app's own origin so the
      // session cookie is sent, which is the whole reason /code is cookie
      // authenticated rather than bearer authenticated.
      el.setAttribute('data-code-url', CODE_PATH)
      el.setAttribute('data-style', cfg.style || 'bubble')
      if (cfg.target) el.setAttribute('data-target', cfg.target)
      if (cfg.label) el.setAttribute('data-label', cfg.label)
      if (cfg.side) el.setAttribute('data-side', cfg.side)
      if (cfg.width) el.setAttribute('data-width', cfg.width)
      if (cfg.height) el.setAttribute('data-height', cfg.height)
      if (cfg.open) el.setAttribute('data-open', 'true')

      el.onerror = () => {
        if (cancelled) return
        scheduleRetry(cfg)
      }

      el.onload = () => {
        if (cancelled) return
        const deadline = Date.now() + INIT_TIMEOUT_MS
        const poll = () => {
          if (cancelled) return
          if (window.Resonance) {
            attemptRef.current = 0
            narrowForInsecureContext(baseUrl)
            return
          }
          if (Date.now() > deadline) {
            scheduleRetry(cfg)
            return
          }
          timerRef.current = window.setTimeout(poll, 250)
        }
        poll()
      }

      scriptRef.current = el
      document.body.appendChild(el)
    }

    // The access token lives in memory, so a reload has none until the app has
    // exchanged its refresh cookie. Layout renders as soon as auth reports a
    // user, which can be a beat before that exchange lands — and this fetch is
    // a raw one, outside the api client, so it does not inherit the client's
    // 401-refresh-and-retry. A single 401 here used to disable the widget for
    // the whole page load, silently. Retry on the same schedule the script
    // loader uses instead.
    const fetchConfig = async (): Promise<ResonanceConfig | null> => {
      for (let attempt = 0; ; attempt++) {
        try {
          const res = await authFetch(CONFIG_PATH)
          if (res.ok) return (await res.json()) as ResonanceConfig
          // 403 and 404 are settled answers — the role is not allowed, or the
          // feature is off. Only a missing credential is worth waiting out.
          if (res.status !== 401) return null
        } catch {
          /* network hiccup on our own origin — treat it like a 401 and retry */
        }
        const delay = CONFIG_RETRY_DELAYS_MS[attempt]
        if (delay === undefined || cancelled) return null
        await new Promise(resolve => { timerRef.current = window.setTimeout(resolve, delay) })
        if (cancelled) return null
      }
    }

    const start = async () => {
      let cfg = configRef.current
      if (!cfg) {
        cfg = await fetchConfig()
        if (!cfg) return
        configRef.current = cfg
      }
      if (cancelled || !cfg?.enabled || !cfg.base_url) return

      const excluded = (cfg.exclude_paths || []).some(
        p => p && (location.pathname === p || location.pathname.startsWith(`${p}/`)),
      )
      if (excluded) {
        teardown()
        return
      }
      if (scriptRef.current) return   // already mounted; a route change is not a reason to remount
      inject(cfg)
    }

    start()

    return () => {
      cancelled = true
      clearTimer()
    }
  }, [location.pathname, getToken])

  // Unmount means the authenticated layout went away — a logout, or a session
  // that expired. The frame holds a resonance session that outlives this app's
  // own, so it must be destroyed rather than left running behind a login screen.
  useEffect(() => {
    return () => {
      try {
        window.Resonance?.destroy?.()
      } catch {
        /* nothing to destroy */
      }
      document.querySelectorAll('script[data-code-url]').forEach(el => el.remove())
    }
  }, [])

  return null
}
