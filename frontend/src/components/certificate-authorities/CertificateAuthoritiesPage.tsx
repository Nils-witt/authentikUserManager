import { useAppContext } from '../../hooks/useAppContext'
import { AccessGate } from '../layout/AccessGate'
import { CertificateAuthorities } from './CertificateAuthorities'

/** The certificate authorities page, for access administrators when certificates are configured. */
export function CertificateAuthoritiesPage() {
  const { access, refresh } = useAppContext()
  return (
    <AccessGate allow={(access?.admin ?? false) && (access?.certificates ?? false)}>
      {/* A changed CA may change the common name suffixes the app knows. */}
      <CertificateAuthorities onChange={refresh} />
    </AccessGate>
  )
}
