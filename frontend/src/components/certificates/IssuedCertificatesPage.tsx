import { useAppContext } from '../../hooks/useAppContext'
import { AccessGate } from '../layout/AccessGate'
import { IssuedCertificates } from './IssuedCertificates'

/** The list of the certificates of all users, for access administrators when a CA is configured. */
export function IssuedCertificatesPage() {
  const { access } = useAppContext()
  return (
    <AccessGate allow={(access?.admin ?? false) && (access?.certificates ?? false)}>
      <IssuedCertificates />
    </AccessGate>
  )
}
