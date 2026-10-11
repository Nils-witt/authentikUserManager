import { useEffect, useState } from 'react'
import * as api from '../api'

/**
 * Loads up to 100 authentik group names, for suggestions. Only access administrators
 * may list them, so pass `enabled` = false for anyone else. Group names are only
 * suggestions, so a failure yields an empty list rather than an error.
 */
export function useGroupNames(enabled = true) {
  const [groupNames, setGroupNames] = useState<string[]>([])

  useEffect(() => {
    if (!enabled) return
    api
      .listGroupNames()
      .then(setGroupNames)
      .catch(() => setGroupNames([]))
  }, [enabled])

  return groupNames
}
