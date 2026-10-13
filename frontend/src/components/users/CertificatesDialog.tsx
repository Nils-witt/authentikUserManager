import Alert from '@mui/material/Alert'
import DialogContent from '@mui/material/DialogContent'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { Certificate, User } from '../../api'
import { errorMessage } from '../../errors'
import { useConfirm } from '../../hooks/useConfirm'
import { CertificateTable } from '../certificates/CertificateTable'
import { Modal } from '../common/Modal'

interface CertificatesDialogProps {
  user: User
  onClose: () => void
  /** Called with a notice after a certificate was revoked. */
  onRevoked: (message: string) => void
}

/**
 * Lists a user's certificates for an operator, who may revoke them. Only the
 * user can issue certificates and download their keys.
 */
export function CertificatesDialog({ user, onClose, onRevoked }: CertificatesDialogProps) {
  // The certificates, or null while loading.
  const [certificates, setCertificates] = useState<Certificate[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  // Bumped after every revocation, to reload the certificates.
  const [version, setVersion] = useState(0)
  const [confirm, confirmDialog] = useConfirm()

  useEffect(() => {
    let cancelled = false
    api
      .listUserCertificates(user.pk)
      .then((list) => {
        if (!cancelled) setCertificates(list)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [user.pk, version])

  async function revoke(c: Certificate) {
    const ok = await confirm({
      title: `Revoke this certificate of ${user.username}?`,
      message: 'It stops working wherever the CRL is checked. This cannot be undone.',
      confirmLabel: 'Revoke',
    })
    if (!ok) return
    setBusy(c.serial)
    setError(null)
    try {
      await api.revokeCertificate(user.pk, c.serial)
      onRevoked(`Certificate of ${user.username} revoked.`)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
      setVersion((v) => v + 1)
    }
  }

  return (
    <Modal title={`Certificates of ${user.username}`} onClose={onClose} wide>
      <DialogContent>
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">
            Users issue certificates for themselves and download the keys. You can revoke them.
          </Typography>
          {error && <Alert severity="error">{error}</Alert>}
          <CertificateTable
            certificates={certificates}
            busy={busy}
            loadFailed={error !== null}
            onRevoke={(c) => void revoke(c)}
          />
        </Stack>
      </DialogContent>
      {confirmDialog}
    </Modal>
  )
}
