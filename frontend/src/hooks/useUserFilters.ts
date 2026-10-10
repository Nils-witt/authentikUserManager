import { useEffect, useState } from 'react'

/** Which users the list shows by their active flag. */
export type StatusFilter = 'all' | 'active' | 'inactive'

/** Search, folder, status and page of the user list; changing a filter returns to page 1. */
export function useUserFilters() {
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  // Selected user folder (path), or null for all users.
  const [folder, setFolder] = useState<string | null>(null)
  const [status, setStatus] = useState<StatusFilter>('all')

  // Debounce the search box so we don't query authentik on every keystroke.
  useEffect(() => {
    const id = setTimeout(() => {
      setQuery(search.trim())
      setPage(1)
    }, 300)
    return () => clearTimeout(id)
  }, [search])

  function selectFolder(path: string | null) {
    setFolder(path)
    setPage(1)
  }

  function selectStatus(value: StatusFilter | null) {
    // Exclusive toggle groups report null when the selected button is clicked again.
    if (value === null) return
    setStatus(value)
    setPage(1)
  }

  return { search, setSearch, query, page, setPage, folder, selectFolder, status, selectStatus }
}
