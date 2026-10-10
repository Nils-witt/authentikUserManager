import { useEffect, useState } from 'react'
import * as api from '../api'
import type { Access } from '../api'
import { errorMessage } from '../errors'

/**
 * Loads which users the operator may manage. Bump `version` after every change,
 * since an edited rule may change the operator's own scope.
 */
export function useAccess(version: number) {
  const [access, setAccess] = useState<Access | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .access()
      .then((value) => {
        setAccess(value)
        setError(null)
      })
      .catch((err: unknown) => setError(errorMessage(err)))
  }, [version])

  // Loaded, but the operator's groups grant access to nobody.
  const noAccess = access !== null && !access.all && access.groups.length === 0
  return { access, noAccess, error }
}
