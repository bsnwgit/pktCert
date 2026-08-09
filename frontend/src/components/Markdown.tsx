import { Fragment, type ReactNode } from 'react'

// Minimal, dependency-free markdown renderer — covers the subset actually
// used in docs/*.md: headings, paragraphs, bold, inline code, links, fenced
// code blocks, ordered/unordered lists, tables, and horizontal rules.

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = []
  const re = /\*\*(.+?)\*\*|`([^`]+)`|\[([^\]]+)\]\(([^)]+)\)/g
  let lastIndex = 0
  let match: RegExpExecArray | null
  let i = 0
  while ((match = re.exec(text)) !== null) {
    if (match.index > lastIndex) nodes.push(text.slice(lastIndex, match.index))
    if (match[1] !== undefined) {
      nodes.push(<strong key={`${keyPrefix}-${i++}`} className="font-semibold text-white">{match[1]}</strong>)
    } else if (match[2] !== undefined) {
      nodes.push(
        <code key={`${keyPrefix}-${i++}`} className="bg-gray-800 text-blue-300 rounded px-1 py-0.5 text-[0.85em]">
          {match[2]}
        </code>,
      )
    } else if (match[3] !== undefined) {
      nodes.push(
        <a key={`${keyPrefix}-${i++}`} href={match[4]} target="_blank" rel="noopener noreferrer"
          className="text-blue-400 hover:text-blue-300 underline underline-offset-2">
          {match[3]}
        </a>,
      )
    }
    lastIndex = re.lastIndex
  }
  if (lastIndex < text.length) nodes.push(text.slice(lastIndex))
  return nodes
}

function parseTableRow(line: string): string[] {
  return line.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim())
}

export default function Markdown({ content }: { content: string }) {
  const lines = content.replace(/\r\n/g, '\n').split('\n')
  const blocks: ReactNode[] = []
  let i = 0
  let key = 0

  while (i < lines.length) {
    const line = lines[i]

    if (line.trim() === '') { i++; continue }

    // Fenced code block
    if (line.startsWith('```')) {
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].startsWith('```')) { codeLines.push(lines[i]); i++ }
      i++ // skip closing fence
      blocks.push(
        <pre key={key++} className="bg-gray-800 border border-gray-700 rounded-lg p-3 overflow-x-auto text-xs text-gray-200 my-3">
          <code>{codeLines.join('\n')}</code>
        </pre>,
      )
      continue
    }

    // Heading
    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/)
    if (headingMatch) {
      const level = headingMatch[1].length
      const text = headingMatch[2]
      const sizes: Record<number, string> = {
        1: 'text-2xl font-bold text-white mt-6 mb-3',
        2: 'text-xl font-semibold text-white mt-6 mb-2 pb-1 border-b border-gray-800',
        3: 'text-base font-semibold text-white mt-4 mb-2',
      }
      const cls = sizes[level] ?? 'text-sm font-semibold text-white mt-3 mb-1'
      const inline = renderInline(text, `h${key}`)
      blocks.push(
        level === 1 ? <h1 key={key++} className={cls}>{inline}</h1> :
        level === 2 ? <h2 key={key++} className={cls}>{inline}</h2> :
        level === 3 ? <h3 key={key++} className={cls}>{inline}</h3> :
        <h4 key={key++} className={cls}>{inline}</h4>
      )
      i++
      continue
    }

    // Horizontal rule
    if (/^(-{3,}|\*{3,})$/.test(line.trim())) {
      blocks.push(<hr key={key++} className="border-gray-800 my-4" />)
      i++
      continue
    }

    // Table
    if (line.trim().startsWith('|')) {
      const header = parseTableRow(line)
      i++
      if (i < lines.length && /^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?$/.test(lines[i].trim())) i++
      const rows: string[][] = []
      while (i < lines.length && lines[i].trim().startsWith('|')) { rows.push(parseTableRow(lines[i])); i++ }
      blocks.push(
        <div key={key++} className="overflow-x-auto my-3">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-gray-700">
                {header.map((h, hi) => (
                  <th key={hi} className="text-left text-white font-semibold px-3 py-1.5">{renderInline(h, `th${key}-${hi}`)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri} className="border-b border-gray-800">
                  {r.map((c, ci) => (
                    <td key={ci} className="text-gray-300 px-3 py-1.5 align-top">{renderInline(c, `td${key}-${ri}-${ci}`)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      )
      continue
    }

    // Unordered list
    if (/^[-*]\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^[-*]\s+/.test(lines[i])) { items.push(lines[i].replace(/^[-*]\s+/, '')); i++ }
      blocks.push(
        <ul key={key++} className="list-disc list-outside pl-5 my-2 space-y-1 text-gray-300">
          {items.map((it, ii) => <li key={ii}>{renderInline(it, `ul${key}-${ii}`)}</li>)}
        </ul>,
      )
      continue
    }

    // Ordered list
    if (/^\d+\.\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\d+\.\s+/.test(lines[i])) { items.push(lines[i].replace(/^\d+\.\s+/, '')); i++ }
      blocks.push(
        <ol key={key++} className="list-decimal list-outside pl-5 my-2 space-y-1 text-gray-300">
          {items.map((it, ii) => <li key={ii}>{renderInline(it, `ol${key}-${ii}`)}</li>)}
        </ol>,
      )
      continue
    }

    // Paragraph — consecutive non-empty, non-special lines joined with spaces
    const paraLines: string[] = []
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !lines[i].startsWith('```') &&
      !/^#{1,6}\s+/.test(lines[i]) &&
      !lines[i].trim().startsWith('|') &&
      !/^[-*]\s+/.test(lines[i]) &&
      !/^\d+\.\s+/.test(lines[i])
    ) {
      paraLines.push(lines[i])
      i++
    }
    blocks.push(
      <p key={key++} className="text-gray-300 leading-relaxed my-2">
        {renderInline(paraLines.join(' '), `p${key}`)}
      </p>,
    )
  }

  return <Fragment>{blocks}</Fragment>
}
