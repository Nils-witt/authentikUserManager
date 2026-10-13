import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import DeleteIcon from '@mui/icons-material/Delete'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import DialogContent from '@mui/material/DialogContent'
import IconButton from '@mui/material/IconButton'
import LinearProgress from '@mui/material/LinearProgress'
import MenuItem from '@mui/material/MenuItem'
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
import { ApiError, type CreatedToken, type Token, type TokenIntent, type User } from '../../api'
import { errorMessage } from '../../errors'
import { useConfirm } from '../../hooks/useConfirm'
import { Modal } from '../common/Modal'

const INTENT_LABELS: Record<TokenIntent, string> = {
  api: 'API token',
  app_password: 'App password',
}

/** The date one year from today, as yyyy-mm-dd: the default expiry of a new token. */
function inOneYear() {
  const d = new Date()
  d.setFullYear(d.getFullYear() + 1)
  return d.toISOString().slice(0, 10)
}

function formatExpiry(token: Token) {
  return token.expiring && token.expires ? new Date(token.expires).toLocaleString() : 'never'
}

interface TokensDialogProps {
  account: User
  onClose: () => void
  /** Called with a notice after a token was created or deleted. */
  onChanged: (message: string) => void
}

/** Lists, creates and deletes the tokens of a service account; a new token's key is shown once. */
export function TokensDialog({ account, onClose, onChanged }: TokensDialogProps) {
  // The tokens, or null while loading.
  const [tokens, setTokens] = useState<Token[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string[]>>({})
  const [intent, setIntent] = useState<TokenIntent>('api')
  const [description, setDescription] = useState('')
  // Expiry date (yyyy-mm-dd); empty for a token that never expires.
  const [expires, setExpires] = useState(inOneYear)
  const [created, setCreated] = useState<CreatedToken | null>(null)
  const [copied, setCopied] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  // Bumped after every change, to reload the tokens.
  const [version, setVersion] = useState(0)
  const [confirm, confirmDialog] = useConfirm()

  useEffect(() => {
    let cancelled = false
    api
      .listTokens(account.pk)
      .then((list) => {
        if (!cancelled) setTokens(list)
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
      // The token expires at the end of the chosen day, in the browser's time zone.
      const expiry = expires ? new Date(`${expires}T23:59:59`).toISOString() : null
      const result = await api.createToken(account.pk, { intent, description, expires: expiry })
      setCreated(result)
      setDescription('')
      onChanged(`Token created for ${account.username}.`)
    } catch (err) {
      setError(errorMessage(err))
      if (err instanceof ApiError) setFields(err.fields)
    } finally {
      setBusy(null)
      setVersion((v) => v + 1)
    }
  }

  async function remove(token: Token) {
    const ok = await confirm({
      title: `Delete the token ${token.identifier}?`,
      message: 'Everything using it can no longer sign in with it. This cannot be undone.',
      confirmLabel: 'Delete',
    })
    if (!ok) return
    setBusy(token.identifier)
    setError(null)
    try {
      await api.deleteToken(account.pk, token.identifier)
      if (created?.token.identifier === token.identifier) setCreated(null)
      onChanged(`Token of ${account.username} deleted.`)
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

  return (
    <Modal title={`Tokens of ${account.username}`} onClose={onClose} wide>
      <DialogContent>
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">
            API tokens authenticate against the authentik API, app passwords sign in to applications
            (e.g. LDAP) as {account.username}. A new token&apos;s key is shown once.
          </Typography>
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
                    aria-label="Token key"
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
                select
                label="Type"
                value={intent}
                onChange={(e) => setIntent(e.target.value as TokenIntent)}
                sx={{ minWidth: 160 }}
                {...fieldError('intent')}
              >
                {Object.entries(INTENT_LABELS).map(([value, label]) => (
                  <MenuItem key={value} value={value}>
                    {label}
                  </MenuItem>
                ))}
              </TextField>
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
          <TableContainer component={Paper} variant="outlined" aria-busy={tokens === null}>
            <Box sx={{ height: 4 }}>{tokens === null && !error && <LinearProgress />}</Box>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Identifier</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Expires</TableCell>
                  <TableCell aria-label="Actions" />
                </TableRow>
              </TableHead>
              <TableBody>
                {tokens?.map((token) => (
                  <TableRow key={token.identifier}>
                    <TableCell sx={{ fontFamily: 'monospace' }}>{token.identifier}</TableCell>
                    <TableCell>{INTENT_LABELS[token.intent] ?? token.intent}</TableCell>
                    <TableCell>{token.description || '—'}</TableCell>
                    <TableCell>{formatExpiry(token)}</TableCell>
                    <TableCell align="right">
                      <Tooltip title={token.managed ? 'Managed by authentik' : 'Delete'}>
                        <span>
                          <IconButton
                            size="small"
                            color="error"
                            disabled={!!token.managed || busy === token.identifier}
                            onClick={() => void remove(token)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
                {tokens?.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                      No tokens.
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
