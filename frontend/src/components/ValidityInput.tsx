import { useState } from 'react'

const DAYS_PER_YEAR = 365

/** Human-friendly rendering of a validity_days value, e.g. 1095 -> "3y", 400 -> "1y 35d", 90 -> "90d". */
export function formatValidity(days: number): string {
  if (days % DAYS_PER_YEAR === 0 && days >= DAYS_PER_YEAR) return `${days / DAYS_PER_YEAR}y`
  const years = Math.floor(days / DAYS_PER_YEAR)
  const rest = days % DAYS_PER_YEAR
  return years > 0 ? `${years}y ${rest}d` : `${days}d`
}

/**
 * Validity period input backed by a plain `validity_days` number, with a Days/Years
 * unit toggle so multi-year certs (CAs especially) don't require mental math into days.
 */
export default function ValidityInput({ days, onChange, className }: {
  days: number
  onChange: (days: number) => void
  className: string
}) {
  const [unit, setUnit] = useState<'days' | 'years'>(days >= DAYS_PER_YEAR && days % DAYS_PER_YEAR === 0 ? 'years' : 'days')
  const displayValue = unit === 'years' ? days / DAYS_PER_YEAR : days

  const setUnitPreservingValue = (next: 'days' | 'years') => {
    if (next === unit) return
    setUnit(next)
    onChange(next === 'years' ? Math.max(1, Math.round(days / DAYS_PER_YEAR)) * DAYS_PER_YEAR : days)
  }

  return (
    <div className="flex gap-2">
      <input type="number" min={1} value={displayValue}
        onChange={e => onChange(unit === 'years' ? Math.max(1, Number(e.target.value)) * DAYS_PER_YEAR : Number(e.target.value))}
        className={className} />
      <div className="flex shrink-0 bg-gray-800 border border-gray-700 rounded-lg p-1">
        {(['days', 'years'] as const).map(u => (
          <button key={u} type="button" onClick={() => setUnitPreservingValue(u)}
            className={`text-xs px-2.5 py-1 rounded-md capitalize transition-colors ${unit === u ? 'bg-gray-700 text-white' : 'text-white hover:text-white'}`}>
            {u}
          </button>
        ))}
      </div>
    </div>
  )
}
