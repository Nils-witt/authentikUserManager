import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import FormControlLabel from '@mui/material/FormControlLabel'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState, type FormEvent } from 'react'
import * as api from '../../api'
import { ApiError, type Group } from '../../api'

interface CreateGroupFormProps {
  /** Suggested folder of the new group, e.g. the one selected in the list. */
  initialPath: string
  /** Receives the group once it was created. */
  onCreated: (group: Group) => void
  onBack: () => void
}

/** Creates a group without members; only access administrators may. */
export function CreateGroupForm({ initialPath, onCreated, onBack }: CreateGroupFormProps) {
  const [name, setName] = useState('')
  const [path, setPath] = useState(initialPath)
  const [visible, setVisible] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const [saving, setSaving] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      onCreated(await api.createGroup({ name: name.trim(), visible, path: path.trim() }))
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, String(err)))
      setSaving(false)
    }
  }

  const nameErrors = error?.fields.name
  const pathErrors = error?.fields.path
  return (
    <form onSubmit={submit}>
      <DialogContent sx={{ pt: 0 }}>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && !nameErrors?.length && !pathErrors?.length && (
            <Alert severity="error">{error.message}</Alert>
          )}
          <TextField
            label="Name"
            required
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            error={Boolean(nameErrors?.length)}
            helperText={
              nameErrors?.join(' ') ?? 'Access rules match groups by name, so it must be unique.'
            }
          />
          <TextField
            label="Path"
            placeholder="e.g. school/classes"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            error={Boolean(pathErrors?.length)}
            helperText={
              pathErrors?.join(' ') ?? 'Sorts the group into folders; empty for the top level.'
            }
          />
          <Stack spacing={0.5}>
            <FormControlLabel
              label="Visible to all signed-in users"
              control={<Switch checked={visible} onChange={(e) => setVisible(e.target.checked)} />}
            />
            <Typography variant="body2" color="text.secondary">
              Everyone who can sign in to this app sees the group&apos;s name, but not its members,
              and may request to join it.
            </Typography>
          </Stack>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onBack}>Back to groups</Button>
        <Button type="submit" variant="contained" loading={saving}>
          Create group
        </Button>
      </DialogActions>
    </form>
  )
}
