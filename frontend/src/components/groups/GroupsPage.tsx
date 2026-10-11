import { useAppContext } from '../../hooks/useAppContext'
import { AccessGate } from '../layout/AccessGate'
import { GroupAdmin } from './GroupAdmin'

/** The groups page, for every operator once their access has loaded. */
export function GroupsPage() {
  const { access, refresh } = useAppContext()
  return (
    <AccessGate allow={access !== null}>
      <GroupAdmin admin={access?.admin ?? false} onChange={refresh} />
    </AccessGate>
  )
}
