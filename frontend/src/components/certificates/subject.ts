/**
 * The common name in a subject distinguished name as Go formats it (RFC 2253, e.g.
 * "CN=ann,O=Example"), unescaped; empty without one.
 */
export function commonName(subject: string): string {
  let attribute = ''
  let value = ''
  let inValue = false
  for (let i = 0; i < subject.length; i++) {
    const ch = subject[i]
    if (ch === '\\' && i + 1 < subject.length) {
      value += subject[++i]
    } else if (!inValue && ch === '=') {
      attribute = value.trim()
      value = ''
      inValue = true
    } else if (ch === ',' || ch === '+') {
      if (attribute.toUpperCase() === 'CN') return value
      value = ''
      inValue = false
    } else {
      value += ch
    }
  }
  return inValue && attribute.toUpperCase() === 'CN' ? value : ''
}
