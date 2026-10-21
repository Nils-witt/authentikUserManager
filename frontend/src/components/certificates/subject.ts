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

/** Joins a user-chosen prefix to the username in a common name. */
export const CN_PREFIX_SEPARATOR = '+'

/** Prefixes the server accepts: 1 to 32 letters, digits, dots, hyphens and underscores. */
export const CN_PREFIX_PATTERN = /^[\p{L}\p{N}._-]{1,32}$/u

/**
 * The username a common name names: without the first of `suffixes` (longest first, as the
 * server lists them) it ends in, unless nothing would be left of it, and without a valid
 * prefix before the first separator. Usernames may hold the separator too, so the result is a
 * suggestion only.
 */
export function usernameFromCommonName(cn: string, suffixes: readonly string[]): string {
  let name = cn
  for (const suffix of suffixes) {
    if (name.endsWith(suffix) && name.length > suffix.length) {
      name = name.slice(0, -suffix.length)
      break
    }
  }
  const i = name.indexOf(CN_PREFIX_SEPARATOR)
  if (i > 0 && i < name.length - 1 && CN_PREFIX_PATTERN.test(name.slice(0, i))) {
    return name.slice(i + 1)
  }
  return name
}
