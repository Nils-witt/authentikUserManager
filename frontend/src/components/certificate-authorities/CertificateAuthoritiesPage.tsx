import { useAppContext } from '../../hooks/useAppContext'
import { AccessGate } from '../layout/AccessGate'
import { CertificateAuthorities } from './CertificateAuthorities'

/**
 * The certificate authorities page, for every user when certificates are configured. Only access
 * administrators may change the CAs.
 */
export function CertificateAuthoritiesPage() {
  const { access, refresh } = useAppContext()
  return (
    <AccessGate allow={access?.certificates ?? false}>
      {/* A changed CA may change the common name suffixes the app knows. */}
      <CertificateAuthorities canManage={access?.admin ?? false} onChange={refresh} />
    </AccessGate>
  )
}
