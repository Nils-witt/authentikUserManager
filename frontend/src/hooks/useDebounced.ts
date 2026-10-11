import { useEffect, useState } from 'react'

/** Returns `value` trimmed once it has not changed for `delay` ms, e.g. to query on pauses in typing. */
export function useDebounced(value: string, delay = 300) {
  const [debounced, setDebounced] = useState(value.trim())

  useEffect(() => {
    const id = setTimeout(() => setDebounced(value.trim()), delay)
    return () => clearTimeout(id)
  }, [value, delay])

  return debounced
}
