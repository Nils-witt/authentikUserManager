import { useAppContext } from '../../hooks/useAppContext'
import { AccessGate } from '../layout/AccessGate'
import { AccessRules } from './AccessRules'

/** The access rules page, for access administrators. */
export function AccessRulesPage() {
  const { access, refresh } = useAppContext()
  return (
    <AccessGate allow={access?.admin ?? false}>
      {/* A changed rule may change the operator's own access. */}
      <AccessRules onChange={refresh} />
    </AccessGate>
  )
}
