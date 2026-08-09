import { useState } from 'react'

/**
 * Step-up re-auth prompt: re-enter the current password to authorize one
 * sensitive action (reveal or download). Always re-prompts — the caller
 * never caches a password across actions, so this mounts fresh each time.
 */
export default function ConfirmPasswordModal({ title, description, onConfirm, onClose }: {
  title: string
  description: string
  onConfirm: (password: string) => Promise<void>
  onClose: () => void
}) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await onConfirm(password)
      onClose()
    } catch (e: any) {
      setError(e.message ?? 'Failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-sm p-6" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
        <p className="text-sm text-white mb-4">{description}</p>
        <form onSubmit={submit} className="space-y-4">
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} autoFocus required
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500" />
          {error && <p className="text-red-400 text-xs">{error}</p>}
          <div className="flex justify-end gap-3">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-white">Cancel</button>
            <button type="submit" disabled={loading || !password}
              className="px-4 py-2 text-sm bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg">
              {loading ? 'Verifying…' : 'Confirm'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
