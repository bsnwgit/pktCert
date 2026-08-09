import { useState, type ReactNode } from 'react'

export default function HelpButton({ title, children }: { title: string; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} title="How this works"
        className="inline-flex items-center justify-center w-4 h-4 rounded-full border border-sky-500 text-sky-400 hover:text-white hover:border-sky-400 hover:bg-sky-500 text-[10px] font-semibold leading-none transition-colors flex-shrink-0">
        ?
      </button>
      {open && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setOpen(false)}>
          <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-xl p-6 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">{title}</h2>
              <button onClick={() => setOpen(false)} className="text-gray-500 hover:text-white text-lg leading-none">×</button>
            </div>
            <div className="text-sm text-gray-400 space-y-3">
              {children}
            </div>
          </div>
        </div>
      )}
    </>
  )
}
