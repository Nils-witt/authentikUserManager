import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router'

/** Which users the list shows by their active flag. */
export type StatusFilter = 'all' | 'active' | 'inactive'

const SEARCH_DELAY = 300

function parseStatus(value: string | null): StatusFilter {
  return value === 'active' || value === 'inactive' ? value : 'all'
}

function parsePage(value: string | null): number {
  const page = Number(value)
  return Number.isInteger(page) && page > 0 ? page : 1
}

/**
 * Search, folder, status and page of the user list, kept in the URL's query so
 * they survive a reload and other pages; changing a filter returns to page 1.
 * Defaults are left out of the URL.
 */
export function useUserFilters() {
  const [params, setParams] = useSearchParams()
  const query = params.get('q') ?? ''
  // Selected user folder (path), or null for all users.
  const folder = params.get('folder')
  const status = parseStatus(params.get('status'))
  const page = parsePage(params.get('page'))

  // The search box, ahead of `query` while the user types.
  const [search, setSearchValue] = useState(query)
  const [syncedQuery, setSyncedQuery] = useState(query)
  if (query !== syncedQuery) {
    // The URL changed elsewhere, e.g. by going back: show its search.
    setSyncedQuery(query)
    if (search.trim() !== query) setSearchValue(query)
  }

  /** Sets the given query parameters (null removes one) and returns to page 1. */
  function update(changes: Record<string, string | null>, replace = false) {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        for (const [key, value] of Object.entries(changes)) {
          if (value === null) next.delete(key)
          else next.set(key, value)
        }
        if (!('page' in changes)) next.delete('page')
        return next
      },
      { replace },
    )
  }

  // Debounce the search box so we don't query authentik on every keystroke.
  const searchTimer = useRef<ReturnType<typeof setTimeout>>(undefined)
  useEffect(() => () => clearTimeout(searchTimer.current), [])

  function setSearch(value: string) {
    setSearchValue(value)
    clearTimeout(searchTimer.current)
    searchTimer.current = setTimeout(() => {
      const q = value.trim()
      // Typing replaces the history entry instead of adding one per pause.
      if (q !== query) update({ q: q || null }, true)
    }, SEARCH_DELAY)
  }

  function setPage(value: number) {
    update({ page: value > 1 ? String(value) : null })
  }

  function selectFolder(path: string | null) {
    update({ folder: path })
  }

  function selectStatus(value: StatusFilter | null) {
    // Exclusive toggle groups report null when the selected button is clicked again.
    if (value === null) return
    update({ status: value === 'all' ? null : value })
  }

  return { search, setSearch, query, page, setPage, folder, selectFolder, status, selectStatus }
}
