import { useOutletContext } from 'react-router'
import type { Access, Me } from '../api'

/** What every page gets from the layout. */
export interface AppContext {
  me: Me
  access: Access | null
  /** Loaded, but the operator's groups grant access to nobody. */
  noAccess: boolean
  accessError: string | null
  /** Operators who manage any users decide the requests to join their groups. */
  canDecideJoins: boolean
  /** Bumped by refresh; pages reload the data a change may have touched. */
  version: number
  /** Call after every change: it may change the operator's own access and the pending requests. */
  refresh: () => void
}

/** Returns the context of the page's layout. */
export function useAppContext() {
  return useOutletContext<AppContext>()
}
