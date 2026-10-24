import UploadFileIcon from '@mui/icons-material/UploadFile'
import Alert from '@mui/material/Alert'
import Autocomplete from '@mui/material/Autocomplete'
import Button from '@mui/material/Button'
import Checkbox from '@mui/material/Checkbox'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import FormControlLabel from '@mui/material/FormControlLabel'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import { useState, type ChangeEvent, type FormEvent } from 'react'
import * as api from '../../api'
import { ApiError, type AuthoritySettings, type CertificateAuthority } from '../../api'
import { errorMessage } from '../../errors'

/** Largest PEM file read into the form. */
const MAX_PEM_BYTES = 256 * 1024

/** Names the server accepts; it checks them too. */
const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/

const DEFAULT_SETTINGS: AuthoritySettings = {
  description: '',
  crl_url: '',
  validity_days: 365,
  crl_validity_days: 30,
  user_cn_suffix: '',
  service_account_cn_suffix: '',
  allowed_groups: [],
}

/** The public URL of the CRL this app serves for the CA named name. */
const crlURL = (name: string) => `${window.location.origin}/pki/${name}/crl`

interface PEMFieldProps {
  label: string
  value: string
  onChange: (value: string) => void
  error?: string
  helperText: string
}

/** A multiline PEM text field with a button loading it from a file. */
function PEMField({ label, value, onChange, error, helperText }: PEMFieldProps) {
  const [fileError, setFileError] = useState<string | null>(null)

  async function loadFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (file.size > MAX_PEM_BYTES) {
      setFileError('The file is too large for a PEM file.')
      return
    }
    setFileError(null)
    onChange(await file.text())
  }

  return (
    <Stack spacing={1}>
      <TextField
        label={label}
        multiline
        minRows={4}
        maxRows={10}
        required
        value={value}
        onChange={(e) => onChange(e.target.value)}
        error={!!(error ?? fileError)}
        helperText={error ?? fileError ?? helperText}
        slotProps={{ htmlInput: { sx: { fontFamily: 'monospace', fontSize: 13 } } }}
      />
      <Button component="label" startIcon={<UploadFileIcon />} sx={{ alignSelf: 'flex-start' }}>
        Load file
        <input
          type="file"
          hidden
          accept=".pem,.crt,.cer,.key,.txt"
          onChange={(e) => void loadFile(e)}
        />
      </Button>
    </Stack>
  )
}

interface AuthorityFormProps {
  /** The CA to edit; a new one is added when undefined. */
  authority?: CertificateAuthority
  /** Known authentik group names, offered as suggestions. */
  groups: string[]
  onCancel: () => void
  onSaved: (saved: CertificateAuthority) => void
}

/**
 * Adds a certificate authority from its certificate and key, or changes the settings of one. Its
 * name, certificate and key never change.
 */
export function AuthorityForm({ authority, groups, onCancel, onSaved }: AuthorityFormProps) {
  const isNew = authority === undefined
  const [name, setName] = useState('')
  const [certificatePEM, setCertificatePEM] = useState('')
  const [keyPEM, setKeyPEM] = useState('')
  const [settings, setSettings] = useState<AuthoritySettings>(
    authority
      ? {
          description: authority.description,
          crl_url: authority.crl_url,
          validity_days: authority.validity_days,
          crl_validity_days: authority.crl_validity_days,
          user_cn_suffix: authority.user_cn_suffix,
          service_account_cn_suffix: authority.service_account_cn_suffix,
          allowed_groups: authority.allowed_groups,
        }
      : DEFAULT_SETTINGS,
  )
  const [disabled, setDisabled] = useState(authority?.disabled ?? false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string[]>>({})

  const caName = authority?.name ?? name.trim()
  const badName = isNew && name !== '' && !NAME_PATTERN.test(name.trim())
  const fieldError = (field: string) => fields[field]?.join(' ')
  const set = <K extends keyof AuthoritySettings>(key: K, value: AuthoritySettings[K]) =>
    setSettings((s) => ({ ...s, [key]: value }))

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (badName || saving) return
    setSaving(true)
    setError(null)
    setFields({})
    try {
      const saved = isNew
        ? await api.createAuthority({
            ...settings,
            name: name.trim(),
            certificate_pem: certificatePEM,
            key_pem: keyPEM,
          })
        : await api.updateAuthority(authority.id, { ...settings, disabled })
      setKeyPEM('')
      onSaved(saved)
    } catch (err) {
      setError(errorMessage(err))
      if (err instanceof ApiError) setFields(err.fields)
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)}>
      <DialogContent sx={{ pt: 0 }}>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          {isNew && (
            <>
              <TextField
                label="Name"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                error={badName || !!fieldError('name')}
                helperText={
                  fieldError('name') ??
                  (badName
                    ? 'Up to 32 lowercase letters, digits and hyphens'
                    : 'Identifies the CA in requests and in its URLs; it cannot be changed')
                }
              />
              <PEMField
                label="CA certificate (PEM)"
                value={certificatePEM}
                onChange={setCertificatePEM}
                error={fieldError('certificate_pem')}
                helperText="The CA certificate, optionally followed by the certificates above it"
              />
              <PEMField
                label="Private key (PEM)"
                value={keyPEM}
                onChange={setKeyPEM}
                error={fieldError('key_pem')}
                helperText="Unencrypted; it is stored encrypted and never shown again"
              />
            </>
          )}
          <TextField
            label="Description"
            value={settings.description}
            onChange={(e) => set('description', e.target.value)}
            helperText="Shown to users choosing a CA"
          />
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label="Certificate validity (days)"
              type="number"
              required
              fullWidth
              value={settings.validity_days}
              onChange={(e) => set('validity_days', Number(e.target.value))}
              helperText="Shortened to the CA's own expiry"
            />
            <TextField
              label="CRL validity (days)"
              type="number"
              required
              fullWidth
              value={settings.crl_validity_days}
              onChange={(e) => set('crl_validity_days', Number(e.target.value))}
              helperText="Until clients fetch a new CRL"
            />
          </Stack>
          <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
            <TextField
              label="CRL URL (optional)"
              fullWidth
              value={settings.crl_url}
              onChange={(e) => set('crl_url', e.target.value)}
              helperText="Embedded in issued certificates as their CRL distribution point"
            />
            <Button
              disabled={caName === '' || badName}
              onClick={() => set('crl_url', crlURL(caName))}
              sx={{ mt: 1, whiteSpace: 'nowrap' }}
            >
              Use this app
            </Button>
          </Stack>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label="User common name suffix"
              fullWidth
              value={settings.user_cn_suffix}
              onChange={(e) => set('user_cn_suffix', e.target.value)}
              helperText="e.g. @example.com"
            />
            <TextField
              label="Service account common name suffix"
              fullWidth
              value={settings.service_account_cn_suffix}
              onChange={(e) => set('service_account_cn_suffix', e.target.value)}
              helperText=" "
            />
          </Stack>
          <Autocomplete
            multiple
            freeSolo
            options={groups.filter((g) => !settings.allowed_groups.includes(g))}
            value={settings.allowed_groups}
            onChange={(_, value) =>
              set('allowed_groups', [...new Set(value.map((v) => v.trim()))].filter(Boolean))
            }
            renderInput={(params) => (
              <TextField
                {...params}
                label="Issues certificates for members of"
                placeholder="Group name, then Enter"
                helperText="Direct members only; leave empty to issue for every account"
              />
            )}
          />
          {!isNew && (
            <FormControlLabel
              label={
                authority.default
                  ? 'Disabled (make another CA the default first)'
                  : 'Disabled: issues no certificates, but still publishes its CRL'
              }
              control={
                <Checkbox
                  checked={disabled}
                  disabled={authority.default}
                  onChange={(e) => setDisabled(e.target.checked)}
                />
              }
            />
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel}>Cancel</Button>
        <Button type="submit" variant="contained" loading={saving} disabled={badName}>
          {isNew ? 'Add' : 'Save'}
        </Button>
      </DialogActions>
    </form>
  )
}
