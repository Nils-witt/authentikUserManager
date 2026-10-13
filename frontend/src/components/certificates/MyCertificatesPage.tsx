import { useAppContext } from '../../hooks/useAppContext'
import { AccessGate } from '../layout/AccessGate'
import { MyCertificates } from './MyCertificates'

/** The page of the signed-in user's own certificates, when a CA is configured. */
export function MyCertificatesPage() {
  const { me, access } = useAppContext()
  return (
    <AccessGate allow={access?.certificates ?? false}>
      <MyCertificates username={me.username} />
    </AccessGate>
  )
}
