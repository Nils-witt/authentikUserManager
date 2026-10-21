import UploadFileIcon from '@mui/icons-material/UploadFile'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import FormControlLabel from '@mui/material/FormControlLabel'
import Paper from '@mui/material/Paper'
import Radio from '@mui/material/Radio'
import RadioGroup from '@mui/material/RadioGroup'
import Stack from '@mui/material/Stack'
import Tab from '@mui/material/Tab'
import Tabs from '@mui/material/Tabs'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState, type ChangeEvent, type FormEvent } from 'react'
import * as api from '../../api'
import { ApiError, type IssueCertificateInput, type IssuedCertificate } from '../../api'
import { errorMessage } from '../../errors'
import { useAppContext } from '../../hooks/useAppContext'
import { CN_PREFIX_PATTERN, CN_PREFIX_SEPARATOR } from './subject'

/** Minimum length of a PKCS#12 password; the server checks it too. */
const MIN_PASSWORD_LENGTH = 8

/** Largest CSR file read into the form. */
const MAX_CSR_BYTES = 64 * 1024

type Mode = 'generate' | 'csr'
type Format = 'pkcs12' | 'pem'

interface IssueCertificateFormProps {
  /** Username of the service account the certificate is for; the signed-in user's own when undefined. */
  owner?: string
  /** Issues the certificate; defaults to one for the signed-in user. */
  issue?: (input: IssueCertificateInput) => Promise<IssuedCertificate>
  /** Called once a certificate was issued, with the format a generated key is downloaded in. */
  onIssued: (issued: IssuedCertificate, format: Format | null) => void
}

/** Issues a certificate for the signed-in user or a service account, for a generated key or for the key of a CSR. */
export function IssueCertificateForm({
  owner,
  issue = api.issueCertificate,
  onIssued,
}: IssueCertificateFormProps) {
  const [mode, setMode] = useState<Mode>('generate')
  const [format, setFormat] = useState<Format>('pkcs12')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [csr, setCsr] = useState('')
  const [prefix, setPrefix] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string[]>>({})

  const mismatch = format === 'pkcs12' && confirmation !== '' && password !== confirmation
  const tooShort = format === 'pkcs12' && password.length < MIN_PASSWORD_LENGTH
  const { me, access } = useAppContext()
  // Only users choose a prefix, for their own certificates.
  const ownCertificate = owner === undefined
  const trimmedPrefix = ownCertificate ? prefix.trim() : ''
  const badPrefix = trimmedPrefix !== '' && !CN_PREFIX_PATTERN.test(trimmedPrefix)
  const commonNamePreview =
    (trimmedPrefix ? trimmedPrefix + CN_PREFIX_SEPARATOR : '') +
    me.username +
    (access?.certificate_user_cn_suffix ?? '')
  const invalid =
    badPrefix || (mode === 'csr' ? csr.trim() === '' : tooShort || password !== confirmation)

  async function loadFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (file.size > MAX_CSR_BYTES) {
      setError('The file is too large for a CSR.')
      return
    }
    setCsr(await file.text())
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (invalid || busy) return
    let input: IssueCertificateInput
    if (mode === 'csr') input = { csr }
    else if (format === 'pkcs12') input = { format, password }
    else input = { format }
    if (trimmedPrefix) input.prefix = trimmedPrefix
    setBusy(true)
    setError(null)
    setFields({})
    try {
      const issued = await issue(input)
      setPassword('')
      setConfirmation('')
      setCsr('')
      setPrefix('')
      onIssued(issued, mode === 'generate' ? format : null)
    } catch (err) {
      setError(errorMessage(err))
      if (err instanceof ApiError) setFields(err.fields)
    } finally {
      setBusy(false)
    }
  }

  const fieldError = (name: string) => fields[name]?.join(' ')

  return (
    <Paper variant="outlined" component="form" onSubmit={(e) => void submit(e)} sx={{ p: 2 }}>
      <Stack spacing={2}>
        <Typography variant="h6" component="h3">
          Issue a certificate
        </Typography>
        <Tabs value={mode} onChange={(_, value: Mode) => setMode(value)} aria-label="Key source">
          <Tab value="generate" label="Generate key" />
          <Tab value="csr" label="Sign CSR" />
        </Tabs>
        {error && <Alert severity="error">{error}</Alert>}
        {ownCertificate && (
          <TextField
            label="Common name prefix (optional)"
            value={prefix}
            onChange={(e) => setPrefix(e.target.value)}
            error={badPrefix || !!fieldError('prefix')}
            helperText={
              fieldError('prefix') ??
              (badPrefix
                ? 'Up to 32 letters, digits, dots, hyphens and underscores'
                : `The common name will be ${commonNamePreview}`)
            }
          />
        )}
        {mode === 'generate' ? (
          <>
            <Typography variant="body2" color="text.secondary">
              A new key is generated for {owner ?? 'you'}. You can download it once, within 15
              minutes; the server forgets it afterwards.
            </Typography>
            <RadioGroup
              value={format}
              onChange={(_, value) => setFormat(value as Format)}
              aria-label="Download format"
            >
              <FormControlLabel
                value="pkcs12"
                control={<Radio />}
                label="PKCS#12 (.p12), protected by a password: for browsers and operating systems"
              />
              <FormControlLabel
                value="pem"
                control={<Radio />}
                label="PEM (.pem), unencrypted key, certificate and CA: for command-line tools"
              />
            </RadioGroup>
            {format === 'pkcs12' && (
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                <TextField
                  label="Password"
                  type="password"
                  autoComplete="new-password"
                  required
                  fullWidth
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  error={!!fieldError('password')}
                  helperText={
                    fieldError('password') ?? `At least ${MIN_PASSWORD_LENGTH} characters`
                  }
                />
                <TextField
                  label="Repeat password"
                  type="password"
                  autoComplete="new-password"
                  required
                  fullWidth
                  value={confirmation}
                  onChange={(e) => setConfirmation(e.target.value)}
                  error={mismatch}
                  helperText={mismatch ? 'The passwords differ' : ' '}
                />
              </Stack>
            )}
          </>
        ) : (
          <>
            <Typography variant="body2" color="text.secondary">
              Keep your own key and paste its certificate signing request, e.g. from{' '}
              <code>openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes</code>. The
              certificate is issued for {owner ?? 'your account'} whatever subject the CSR asks for.
            </Typography>
            <TextField
              label="Certificate signing request (PEM)"
              multiline
              minRows={6}
              required
              value={csr}
              onChange={(e) => setCsr(e.target.value)}
              error={!!fieldError('csr')}
              helperText={fieldError('csr') ?? ' '}
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
                accept=".csr,.req,.pem,.txt"
                onChange={(e) => void loadFile(e)}
              />
            </Button>
          </>
        )}
        <Button
          type="submit"
          variant="contained"
          loading={busy}
          disabled={invalid}
          sx={{ alignSelf: 'flex-start' }}
        >
          Issue certificate
        </Button>
      </Stack>
    </Paper>
  )
}
