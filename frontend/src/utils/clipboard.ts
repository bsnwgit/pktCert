/**
 * Copy text to the clipboard, working over plain HTTP too.
 *
 * navigator.clipboard is only exposed in "secure contexts" (HTTPS or
 * localhost) — these apps default to plain http://SERVER-IP, so the
 * Clipboard API is simply undefined there and calling .writeText on it
 * throws immediately, silently no-opping every "Copy" button. Fall back to
 * the classic hidden-textarea + execCommand('copy') trick, which works
 * regardless of secure-context.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // fall through to the legacy fallback below
    }
  }

  try {
    const textarea = document.createElement('textarea')
    textarea.value = text
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    textarea.style.left = '-9999px'
    document.body.appendChild(textarea)
    textarea.focus()
    textarea.select()
    const success = document.execCommand('copy')
    document.body.removeChild(textarea)
    return success
  } catch {
    return false
  }
}
