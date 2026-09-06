// Display-only parsing. The original payload remains untouched for search and copy.
export function parseLogEntry(raw: string) {
  const text = raw.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
  const fields: { key: string; value: string }[] = []
  let message = '',
    time = '',
    level = ''
  function add(key: string, value: string) {
    if (key === 'msg' || key === 'message') message = value
    else if (key === 'time' || key === 'timestamp') time = value
    else if (key === 'level') level = value
    else fields.push({ key, value })
  }
  try {
    const object = JSON.parse(text)
    if (object && typeof object === 'object' && !Array.isArray(object)) {
      for (const [key, value] of Object.entries(object))
        add(key, typeof value === 'string' ? value : JSON.stringify(value))
      return { message: message || '日志记录', time, level, fields }
    }
  } catch {
    /* Logfmt and plain text are expected too. */
  }
  const pattern =
    /(?:^|\s)([\w.-]+)=("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"']+)/g
  let cursor = 0
  const remaining: string[] = []
  for (const match of text.matchAll(pattern)) {
    remaining.push(text.slice(cursor, match.index))
    let value = match[2]!
    if (value.startsWith('"')) {
      try {
        value = JSON.parse(value)
      } catch {
        value = value.slice(1, -1)
      }
    } else if (value.startsWith("'")) value = value.slice(1, -1)
    add(match[1]!, value)
    cursor = match.index! + match[0].length
  }
  remaining.push(text.slice(cursor))
  const rest = remaining.join(' ').trim()
  return {
    message: [message, rest].filter(Boolean).join(' · ') || '日志记录',
    time,
    level,
    fields,
  }
}
