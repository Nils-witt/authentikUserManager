import { useEffect, useState } from 'react'
import * as api from '../api'

/**
 * Counts the pending join requests the operator may decide, when `enabled`.
 * Bump `version` to count again. A failure counts as none; the requests
 * page reports it when opened.
 */
export function useJoinRequestCount(enabled: boolean, version: number) {
  const [count, setCount] = useState(0)

  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    api
      .listJoinRequests()
      .then((requests) => {
        if (!cancelled) setCount(requests.length)
      })
      .catch(() => {
        if (!cancelled) setCount(0)
      })
    return () => {
      cancelled = true
    }
  }, [enabled, version])

  return enabled ? count : 0
}
