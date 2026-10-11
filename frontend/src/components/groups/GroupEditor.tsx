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
import { GroupMembers } from './GroupMembers'

interface GroupEditorProps {
  group: Group
  /** Receives the group after it was renamed, moved or its visibility changed. */
  onUpdated: (group: Group) => void
  onBack: () => void
}

/** Renames one group, moves it to a folder, sets its visibility and edits its direct members. */
export function GroupEditor({ group, onUpdated, onBack }: GroupEditorProps) {
  const [name, setName] = useState(group.name)
  const [path, setPath] = useState(group.path)
  const [savingPath, setSavingPath] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [savingVisibility, setSavingVisibility] = useState(false)
  const unchanged = name.trim() === group.name

  async function rename(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setNotice(null)
    try {
      const renamed = await api.updateGroup(group.pk, { name: name.trim() })
      setName(renamed.name)
      setNotice(`Renamed to ${renamed.name}.`)
      onUpdated(renamed)
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, String(err)))
    } finally {
      setSaving(false)
    }
  }

  async function move(e: FormEvent) {
    e.preventDefault()
    setSavingPath(true)
    setError(null)
    setNotice(null)
    try {
      const moved = await api.updateGroup(group.pk, { path: path.trim() })
      setPath(moved.path)
      setNotice(moved.path ? `Moved to ${moved.path}.` : 'Moved to the top level.')
      onUpdated(moved)
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, String(err)))
    } finally {
      setSavingPath(false)
    }
  }

  async function setVisible(visible: boolean) {
    setSavingVisibility(true)
    setError(null)
    setNotice(null)
    try {
      onUpdated(await api.updateGroup(group.pk, { visible }))
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, String(err)))
    } finally {
      setSavingVisibility(false)
    }
  }

  const nameErrors = error?.fields.name
  const pathErrors = error?.fields.path
  return (
    <>
      <DialogContent sx={{ pt: 0 }}>
        <Stack spacing={3} sx={{ pt: 1 }}>
          <Stack component="form" spacing={1} onSubmit={rename}>
            {error && !nameErrors?.length && !pathErrors?.length && (
              <Alert severity="error">{error.message}</Alert>
            )}
            {notice && <Alert severity="success">{notice}</Alert>}
            <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
              <TextField
                label="Name"
                required
                size="small"
                value={name}
                onChange={(e) => setName(e.target.value)}
                error={Boolean(nameErrors?.length)}
                helperText={nameErrors?.join(' ')}
                sx={{ flexGrow: 1 }}
              />
              <Button type="submit" variant="contained" loading={saving} disabled={unchanged}>
                Rename
              </Button>
            </Stack>
            <Typography variant="body2" color="text.secondary">
              Access rules naming this group are renamed with it. Operators who are members of it
              must sign in again before the renamed rules apply to them.
            </Typography>
          </Stack>
          <Stack component="form" spacing={1} onSubmit={move}>
            <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
              <TextField
                label="Path"
                size="small"
                placeholder="e.g. school/classes"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                error={Boolean(pathErrors?.length)}
                helperText={pathErrors?.join(' ')}
                sx={{ flexGrow: 1 }}
              />
              <Button
                type="submit"
                variant="contained"
                loading={savingPath}
                disabled={path.trim() === group.path}
              >
                Move
              </Button>
            </Stack>
            <Typography variant="body2" color="text.secondary">
              Sorts the group into folders, like the paths of users. Leave it empty for the top
              level.
            </Typography>
          </Stack>
          <Stack spacing={0.5}>
            <FormControlLabel
              label="Visible to all signed-in users"
              control={
                <Switch
                  checked={group.visible}
                  disabled={savingVisibility}
                  onChange={(e) => void setVisible(e.target.checked)}
                />
              }
            />
            <Typography variant="body2" color="text.secondary">
              Everyone who can sign in to this app sees the group&apos;s name, but not its members.
            </Typography>
          </Stack>
          <GroupMembers group={group} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onBack}>Back to groups</Button>
      </DialogActions>
    </>
  )
}
