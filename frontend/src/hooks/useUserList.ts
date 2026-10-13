import { useEffect, useState } from 'react'
import * as api from '../api'
import type { AccountListParams, UserList } from '../api'
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

/**
 * Loads one page of users, or of service accounts with `list`; bump `version` to refetch it after
 * a mutation. `list` must be a stable function, such as one exported by the api module.
 */
export function useUserList(
  { query, folder, status, page }: UserListParams,
  version: number,
  list: (params: AccountListParams) => Promise<UserList> = api.listUsers,
) {
  const [data, setData] = useState<UserList | null>(null)
  const [error, setError] = useState<string | null>(null)
  const requestKey = `${query}|${folder}|${status}|${page}|${version}`
  const [loadedKey, setLoadedKey] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    list({
      search: query,
      page,
      pageSize: PAGE_SIZE,
      path: folder ?? undefined,
      active: status === 'all' ? undefined : status === 'active',
    })
      .then((result) => {
        if (cancelled) return
        setData(result)
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
  }, [list, query, folder, status, page, requestKey])

  return { data, error, loading: loadedKey !== requestKey }
}
