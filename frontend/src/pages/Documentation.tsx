import { useEffect, useState } from 'react'
import { api } from '../api/client'
import Markdown from '../components/Markdown'
import clsx from 'clsx'

interface DocMeta { slug: string; title: string }

export default function Documentation() {
  const [docs, setDocs] = useState<DocMeta[]>([])
  const [active, setActive] = useState<string | null>(null)
  const [content, setContent] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.getDocs()
      .then(list => {
        setDocs(list)
        if (list.length > 0) setActive(list[0].slug)
      })
      .catch(e => setError(e.message ?? 'Failed to load documentation'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!active || content[active] !== undefined) return
    api.getDoc(active)
      .then(doc => setContent(prev => ({ ...prev, [active]: doc.content })))
      .catch(e => setContent(prev => ({ ...prev, [active]: `_Failed to load: ${e.message ?? 'error'}_` })))
  }, [active])

  if (loading) return <div className="text-white text-sm">Loading…</div>
  if (error) return <div className="text-red-400 text-sm">{error}</div>

  if (docs.length === 0) {
    return <div className="text-white text-sm">No documentation is available for this app yet.</div>
  }

  return (
    <div>
      <h1 className="text-xl font-semibold text-white mb-4">Documentation</h1>
      <div className="border-b border-gray-800 flex gap-1 mb-5 overflow-x-auto">
        {docs.map(d => (
          <button
            key={d.slug}
            onClick={() => setActive(d.slug)}
            className={clsx(
              'px-4 py-2 text-sm whitespace-nowrap border-b-2 -mb-px transition-colors',
              active === d.slug
                ? 'border-blue-500 text-blue-300 font-medium'
                : 'border-transparent text-white hover:text-white hover:border-gray-600',
            )}
          >
            {d.title}
          </button>
        ))}
      </div>
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 max-w-4xl">
        {active && content[active] === undefined ? (
          <div className="text-white text-sm">Loading…</div>
        ) : (
          active && <Markdown content={content[active]} />
        )}
      </div>
    </div>
  )
}
