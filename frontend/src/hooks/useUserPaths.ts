import { useEffect, useState } from 'react'
import * as api from '../api'
import { errorMessage } from '../errors'

/** Loads the user folders; bump `version` after mutations, since a user's path may have changed. */
export function useUserPaths(version: number) {
  const [paths, setPaths] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .listUserPaths()
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
  }, [version])

  return { paths, error }
}
