import { useEffect, useState } from 'react'
import * as api from '../api'

/** How often the unread count is refreshed while the page is open. */
const POLL_INTERVAL_MS = 60_000

/**
 * Counts the signed-in user's unread notifications, again every minute, when the window
 * regains focus, and whenever `version` changes. `available` is false when the user receives
 * no notifications: notifications are disabled, or they have no internal account. Another
 * failure counts as none; the notifications page reports it when opened.
 */
export function useNotificationCount(version: number) {
  const [count, setCount] = useState(0)
  const [available, setAvailable] = useState(true)

  useEffect(() => {
    let cancelled = false
    const load = () => {
      api
        .countUnreadNotifications()
        .then((unread) => {
          if (cancelled) return
          setCount(unread)
          setAvailable(true)
        })
        .catch((err: unknown) => {
          if (cancelled) return
          setCount(0)
          if (err instanceof api.ApiError && (err.status === 403 || err.status === 501)) {
            setAvailable(false)
          }
        })
    }
    load()
    const id = setInterval(load, POLL_INTERVAL_MS)
    window.addEventListener('focus', load)
    return () => {
      cancelled = true
      clearInterval(id)
      window.removeEventListener('focus', load)
    }
  }, [version])

  return { count, available }
}
