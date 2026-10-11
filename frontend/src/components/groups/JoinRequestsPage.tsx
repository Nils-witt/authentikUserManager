import { useAppContext } from '../../hooks/useAppContext'
import { AccessGate } from '../layout/AccessGate'
import { JoinRequests } from './JoinRequests'

/** The join requests page, for operators who manage any users. */
export function JoinRequestsPage() {
  const { canDecideJoins, refresh } = useAppContext()
  return (
    <AccessGate allow={canDecideJoins}>
      {/* Approving a request changes the user's groups. */}
      <JoinRequests onChange={refresh} />
    </AccessGate>
  )
}
