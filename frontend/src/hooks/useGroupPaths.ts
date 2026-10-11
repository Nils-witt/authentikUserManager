import { useEffect, useState } from 'react'
import * as api from '../api'
import { errorMessage } from '../errors'

/** Loads the group folders; bump `version` after a group was edited, since its path may have changed. */
export function useGroupPaths(version: number) {
  const [paths, setPaths] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .listGroupPaths()
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
