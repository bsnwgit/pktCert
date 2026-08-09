export function safeFilename(name: string): string {
  return name.replace(/[^\w.-]+/g, '_')
}

export function downloadFile(filename: string, content: string, mime = 'application/x-pem-file') {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
