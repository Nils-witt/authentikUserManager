import UploadFileIcon from '@mui/icons-material/UploadFile'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Checkbox from '@mui/material/Checkbox'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import FormControlLabel from '@mui/material/FormControlLabel'
import List from '@mui/material/List'
import ListItem from '@mui/material/ListItem'
import ListItemText from '@mui/material/ListItemText'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState, type ChangeEvent, type FormEvent } from 'react'
import * as api from '../../api'
import { ApiError, type ImportResult } from '../../api'
import { errorMessage } from '../../errors'
import { Modal } from '../common/Modal'

/** Largest certificate file read into the form; the server accepts 1 MiB bodies. */
const MAX_FILE_BYTES = 512 * 1024

function resultText(r: ImportResult) {
  if (!r.certificate) return `Not imported: ${r.error ?? 'unknown error'}`
  const imported = r.certificate.revoked_at ? 'Imported as revoked' : 'Imported'
  if (r.unassigned) return `${imported} without a user: ${r.unassigned}`
  return `${imported} for ${r.certificate.username}`
}

function resultColor(r: ImportResult) {
  if (!r.certificate) return 'error'
  return r.unassigned ? 'warning.main' : 'success.main'
}

interface ImportCertificatesDialogProps {
  onClose: () => void
  /** Called with the number of certificates imported, when there are any. */
  onImported: (count: number) => void
}

/**
 * Lets access administrators import PEM certificates the CA signed outside this application, so
 * they are listed and can be revoked. Shows the outcome of each certificate.
 */
export function ImportCertificatesDialog({ onClose, onImported }: ImportCertificatesDialogProps) {
  const [pem, setPem] = useState('')
  const [allowUnassigned, setAllowUnassigned] = useState(false)
  const [revoke, setRevoke] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fieldError, setFieldError] = useState<string | null>(null)
  const [results, setResults] = useState<ImportResult[] | null>(null)

  async function loadFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (file.size > MAX_FILE_BYTES) {
      setError('The file is too large.')
      return
    }
    setPem(await file.text())
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (busy || pem.trim() === '') return
    setBusy(true)
    setError(null)
    setFieldError(null)
    try {
      const res = await api.importCertificates(pem, { allowUnassigned, revoke })
      setResults(res)
      const count = res.filter((r) => r.certificate).length
      if (count > 0) onImported(count)
    } catch (err) {
      setError(errorMessage(err))
      if (err instanceof ApiError) setFieldError(err.fields.pem?.join(' ') ?? null)
    } finally {
      setBusy(false)
    }
  }

  if (results) {
    return (
      <Modal title="Import results" onClose={onClose} wide>
        <DialogContent>
          <List dense disablePadding>
            {results.map((r, i) => (
              <ListItem key={`${i}-${r.serial}`} disableGutters>
                <ListItemText
                  primary={resultText(r)}
                  secondary={`${r.subject} · serial ${r.serial}`}
                  slotProps={{
                    primary: { color: resultColor(r) },
                    secondary: { sx: { wordBreak: 'break-all' } },
                  }}
                />
              </ListItem>
            ))}
          </List>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setResults(null)}>Import more</Button>
          <Button variant="contained" onClick={onClose}>
            Done
          </Button>
        </DialogActions>
      </Modal>
    )
  }

  return (
    <Modal title="Import certificates" onClose={onClose} wide>
      <form onSubmit={(e) => void submit(e)}>
        <DialogContent>
          <Stack spacing={2}>
            <Typography variant="body2" color="text.secondary">
              Paste certificates the configured CA signed outside this application, e.g. with
              openssl, to list them here and revoke them through the CRL. Each certificate is
              assigned to the active user or service account named by its common name; one holding a{' '}
              <code>urn:uuid</code> SAN must match that account&apos;s UUID. Expired certificates
              and those of other CAs are rejected, CA certificates skipped, and private keys
              ignored.
            </Typography>
            {error && <Alert severity="error">{error}</Alert>}
            <TextField
              label="Certificates (PEM)"
              multiline
              minRows={8}
              maxRows={16}
              required
              value={pem}
              onChange={(e) => setPem(e.target.value)}
              error={!!fieldError}
              helperText={fieldError ?? 'Up to 100 certificates at once'}
              slotProps={{ htmlInput: { sx: { fontFamily: 'monospace', fontSize: 13 } } }}
            />
            <Button
              component="label"
              startIcon={<UploadFileIcon />}
              sx={{ alignSelf: 'flex-start' }}
            >
              Load file
              <input
                type="file"
                hidden
                accept=".pem,.crt,.cer,.txt"
                onChange={(e) => void loadFile(e)}
              />
            </Button>
            <FormControlLabel
              control={
                <Checkbox
                  checked={allowUnassigned}
                  onChange={(e) => setAllowUnassigned(e.target.checked)}
                />
              }
              label="Import certificates without a matching account, assigned to no user, instead of rejecting them"
            />
            <FormControlLabel
              control={<Checkbox checked={revoke} onChange={(e) => setRevoke(e.target.checked)} />}
              label="Revoke the imported certificates right away, listing them in the CRL"
            />
            {revoke && (
              <Alert severity="warning">
                Revocation cannot be undone: the certificates stop working wherever the CRL is
                checked.
              </Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="submit"
            variant="contained"
            color={revoke ? 'error' : 'primary'}
            loading={busy}
            disabled={pem.trim() === ''}
          >
            {revoke ? 'Import and revoke' : 'Import'}
          </Button>
        </DialogActions>
      </form>
    </Modal>
  )
}
