import { useEffect, useState } from 'react'
import * as api from '../api'
import type { UserList } from '../api'
import { errorMessage } from '../errors'
import type { StatusFilter } from './useUserFilters'

const PAGE_SIZE = 20

interface UserListParams {
  /** Debounced search term. */
  query: string
  folder: string | null
  status: StatusFilter
  page: number
}

/** Loads one page of users; bump `version` to refetch it after a mutation. */
export function useUserList({ query, folder, status, page }: UserListParams, version: number) {
  const [data, setData] = useState<UserList | null>(null)
  const [error, setError] = useState<string | null>(null)
  const requestKey = `${query}|${folder}|${status}|${page}|${version}`
  const [loadedKey, setLoadedKey] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .listUsers({
        search: query,
        page,
        pageSize: PAGE_SIZE,
        path: folder ?? undefined,
        active: status === 'all' ? undefined : status === 'active',
      })
      .then((list) => {
        if (cancelled) return
        setData(list)
        setError(null)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
      .finally(() => {
        if (!cancelled) setLoadedKey(requestKey)
      })
    return () => {
      cancelled = true
    }
  }, [query, folder, status, page, requestKey])

  return { data, error, loading: loadedKey !== requestKey }
}
