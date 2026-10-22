import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import DeleteIcon from '@mui/icons-material/Delete'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import DialogContent from '@mui/material/DialogContent'
import IconButton from '@mui/material/IconButton'
import LinearProgress from '@mui/material/LinearProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import TextField from '@mui/material/TextField'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { useEffect, useState, type FormEvent } from 'react'
import * as api from '../../api'
import { ApiError, type ApiKey, type CreatedApiKey, type User } from '../../api'
import { errorMessage } from '../../errors'
import { useConfirm } from '../../hooks/useConfirm'
import { Modal } from '../common/Modal'

/** The date one year from today, as yyyy-mm-dd: the default expiry of a new key. */
function inOneYear() {
  const d = new Date()
  d.setFullYear(d.getFullYear() + 1)
  return d.toISOString().slice(0, 10)
}

const formatTime = (time: string | null, fallback: string) =>
  time ? new Date(time).toLocaleString() : fallback

interface ApiKeysDialogProps {
  account: User
  onClose: () => void
  /** Called with a notice after a key was created or deleted. */
  onChanged: (message: string) => void
}

/**
 * Lists, creates and deletes the API keys with which a service account issues and revokes its
 * own certificates through the service API; a new key is shown once.
 */
export function ApiKeysDialog({ account, onClose, onChanged }: ApiKeysDialogProps) {
  // The keys, or null while loading.
  const [keys, setKeys] = useState<ApiKey[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string[]>>({})
  const [description, setDescription] = useState('')
  // Expiry date (yyyy-mm-dd); empty for a key that never expires.
  const [expires, setExpires] = useState(inOneYear)
  const [created, setCreated] = useState<CreatedApiKey | null>(null)
  const [copied, setCopied] = useState(false)
  // 'create' or the ID of the key being deleted.
  const [busy, setBusy] = useState<string | number | null>(null)
  // Bumped after every change, to reload the keys.
  const [version, setVersion] = useState(0)
  const [confirm, confirmDialog] = useConfirm()

  useEffect(() => {
    let cancelled = false
    api
      .listApiKeys(account.pk)
      .then((list) => {
        if (!cancelled) setKeys(list)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [account.pk, version])

  async function create(e: FormEvent) {
    e.preventDefault()
    setBusy('create')
    setError(null)
    setFields({})
    setCreated(null)
    setCopied(false)
    try {
      // The key expires at the end of the chosen day, in the browser's time zone.
      const expiry = expires ? new Date(`${expires}T23:59:59`).toISOString() : null
      const result = await api.createApiKey(account.pk, { description, expires: expiry })
      setCreated(result)
      setDescription('')
      onChanged(`API key created for ${account.username}.`)
    } catch (err) {
      setError(errorMessage(err))
      if (err instanceof ApiError) setFields(err.fields)
    } finally {
      setBusy(null)
      setVersion((v) => v + 1)
    }
  }

  async function remove(key: ApiKey) {
    const ok = await confirm({
      title: `Delete the API key ${key.start}…?`,
      message:
        'Everything using it can no longer issue or revoke certificates. This cannot be undone.',
      confirmLabel: 'Delete',
    })
    if (!ok) return
    setBusy(key.id)
    setError(null)
    try {
      await api.deleteApiKey(account.pk, key.id)
      if (created?.api_key.id === key.id) setCreated(null)
      onChanged(`API key of ${account.username} deleted.`)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
      setVersion((v) => v + 1)
    }
  }

  async function copyKey(key: string) {
    try {
      await navigator.clipboard.writeText(key)
      setCopied(true)
    } catch {
      setError('Copying failed; select the key and copy it yourself.')
    }
  }

  const fieldError = (name: string) =>
    fields[name]?.length ? { error: true, helperText: fields[name].join(' ') } : {}

  const endpoint = `${window.location.origin}/service-api/v1/certificates`

  return (
    <Modal title={`API keys of ${account.username}`} onClose={onClose} wide>
      <DialogContent>
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">
            With an API key, {account.username} issues certificates for its own CSRs and revokes its
            own certificates through the service API. A new key is shown once.
          </Typography>
          <Box
            component="pre"
            sx={{
              m: 0,
              p: 1.5,
              borderRadius: 1,
              bgcolor: 'action.hover',
              fontSize: '0.8rem',
              overflowX: 'auto',
            }}
          >
            {`# Issue a certificate for a CSR
jq -Rs '{csr: .}' client.csr | curl -sS -H "Authorization: Bearer $API_KEY" \\
  -H 'Content-Type: application/json' -d @- ${endpoint}
# List the certificates
curl -sS -H "Authorization: Bearer $API_KEY" ${endpoint}
# Revoke a certificate
curl -sS -X POST -H "Authorization: Bearer $API_KEY" ${endpoint}/$SERIAL/revoke`}
          </Box>
          {error && <Alert severity="error">{error}</Alert>}
          {created && (
            <Alert severity="warning">
              <Stack spacing={1}>
                <span>Copy the key now: it is not shown again.</span>
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <TextField
                    size="small"
                    fullWidth
                    value={created.key}
                    aria-label="API key"
                    slotProps={{
                      htmlInput: { readOnly: true, sx: { fontFamily: 'monospace' } },
                    }}
                    onFocus={(e) => e.target.select()}
                  />
                  <Button startIcon={<ContentCopyIcon />} onClick={() => void copyKey(created.key)}>
                    {copied ? 'Copied' : 'Copy'}
                  </Button>
                </Stack>
              </Stack>
            </Alert>
          )}
          <Paper variant="outlined" component="form" onSubmit={(e) => void create(e)} sx={{ p: 2 }}>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                label="Description"
                fullWidth
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                slotProps={{ htmlInput: { maxLength: 255 } }}
                {...fieldError('description')}
              />
              <TextField
                label="Expires"
                type="date"
                value={expires}
                onChange={(e) => setExpires(e.target.value)}
                slotProps={{ inputLabel: { shrink: true } }}
                sx={{ minWidth: 170 }}
                {...fieldError('expires')}
                helperText={fields.expires?.join(' ') ?? 'Empty: never'}
              />
              <Button
                type="submit"
                variant="contained"
                loading={busy === 'create'}
                disabled={!account.is_active}
                sx={{ alignSelf: { sm: 'flex-start' }, mt: { sm: 1 } }}
              >
                Create
              </Button>
            </Stack>
          </Paper>
          <TableContainer component={Paper} variant="outlined" aria-busy={keys === null}>
            <Box sx={{ height: 4 }}>{keys === null && !error && <LinearProgress />}</Box>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Key</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell>Expires</TableCell>
                  <TableCell>Last used</TableCell>
                  <TableCell aria-label="Actions" />
                </TableRow>
              </TableHead>
              <TableBody>
                {keys?.map((key) => (
                  <TableRow key={key.id}>
                    <TableCell sx={{ fontFamily: 'monospace' }}>{key.start}…</TableCell>
                    <TableCell>{key.description || '—'}</TableCell>
                    <TableCell>
                      {formatTime(key.created_at, '—')} by {key.created_by}
                    </TableCell>
                    <TableCell>{formatTime(key.expires_at, 'never')}</TableCell>
                    <TableCell>{formatTime(key.last_used_at, 'never')}</TableCell>
                    <TableCell align="right">
                      <Tooltip title="Delete">
                        <span>
                          <IconButton
                            size="small"
                            color="error"
                            disabled={busy === key.id}
                            onClick={() => void remove(key)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
                {keys?.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                      No API keys.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Stack>
      </DialogContent>
      {confirmDialog}
    </Modal>
  )
}
