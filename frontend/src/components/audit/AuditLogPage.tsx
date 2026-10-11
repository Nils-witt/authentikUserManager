import { useAppContext } from '../../hooks/useAppContext'
import { AccessGate } from '../layout/AccessGate'
import { AuditLog } from './AuditLog'

/** The audit log page, for access administrators. */
export function AuditLogPage() {
  const { access } = useAppContext()
  return (
    <AccessGate allow={access?.admin ?? false}>
      <AuditLog />
    </AccessGate>
  )
}
