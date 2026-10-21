import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState, type FormEvent } from 'react'
import * as api from '../../api'
import { ApiError, type Certificate } from '../../api'
import { errorMessage } from '../../errors'
import { useAppContext } from '../../hooks/useAppContext'
import { Modal } from '../common/Modal'
import { commonName, usernameFromCommonName } from './subject'

interface AssignCertificateDialogProps {
  certificate: Certificate
  onClose: () => void
  /** Called with the certificate once it is assigned. */
  onAssigned: (c: Certificate) => void
}

/**
 * Lets access administrators assign an unassigned imported certificate to a user or service
 * account of their choice, suggesting the one named by its common name.
 */
export function AssignCertificateDialog({
  certificate,
  onClose,
  onAssigned,
}: AssignCertificateDialogProps) {
  const { access } = useAppContext()
  const cn = commonName(certificate.subject)
  const named = usernameFromCommonName(cn, access?.certificate_cn_suffixes ?? [])
  const [username, setUsername] = useState(named)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fieldError, setFieldError] = useState<string | null>(null)

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (busy || username.trim() === '') return
    setBusy(true)
    setError(null)
    setFieldError(null)
    try {
      onAssigned(await api.assignCertificate(certificate.serial, username.trim()))
    } catch (err) {
      setError(errorMessage(err))
      if (err instanceof ApiError) setFieldError(err.fields.username?.join(' ') ?? null)
    } finally {
      setBusy(false)
    }
  }

  const differs = named !== '' && username.trim() !== '' && username.trim() !== named
  return (
    <Modal title="Assign certificate" onClose={onClose}>
      <form onSubmit={(e) => void submit(e)}>
        <DialogContent>
          <Stack spacing={2}>
            <Typography variant="body2" color="text.secondary">
              Assigns the certificate with serial <code>{certificate.serial}</code> to an active
              user or service account, which can then list it and whose deletion revokes it.
            </Typography>
            {error && <Alert severity="error">{error}</Alert>}
            <TextField
              label="Username"
              required
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              error={!!fieldError}
              helperText={
                fieldError ??
                (cn ? `Its common name is ${cn}` : 'The certificate has no common name')
              }
            />
            {differs && (
              <Alert severity="warning">
                The certificate still names {cn}; relying parties that identify certificates by
                their common name do not see it as {username.trim()}&apos;s.
              </Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="submit"
            variant="contained"
            loading={busy}
            disabled={username.trim() === ''}
          >
            Assign
          </Button>
        </DialogActions>
      </form>
    </Modal>
  )
}
