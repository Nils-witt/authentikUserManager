import { useEffect, useState } from 'react'
import * as api from '../api'
import { errorMessage } from '../errors'

/**
 * Loads the user folders, or those of service accounts with `list`; bump `version` after mutations,
 * since an account's path may have changed. `list` must be a stable function, such as one exported
 * by the api module.
 */
export function useUserPaths(version: number, list: () => Promise<string[]> = api.listUserPaths) {
  const [paths, setPaths] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    list()
      .then((list) => {
        if (cancelled) return
        setPaths(list)
        setError(null)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [list, version])

  return { paths, error }
}
