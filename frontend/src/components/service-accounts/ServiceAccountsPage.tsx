import { useAppContext } from '../../hooks/useAppContext'
import { AccessGate } from '../layout/AccessGate'
import { ServiceAccounts } from './ServiceAccounts'

/** The page of the service accounts, for operators who may manage any accounts. */
export function ServiceAccountsPage() {
  const { noAccess } = useAppContext()
  return (
    <AccessGate allow={!noAccess}>
      <ServiceAccounts />
    </AccessGate>
  )
}
