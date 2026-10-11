import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState, type FormEvent } from 'react'
import * as api from '../../api'
import { ApiError, type Group } from '../../api'
import { GroupMembers } from './GroupMembers'

interface GroupEditorProps {
  group: Group
  /** Receives the group after it was renamed. */
  onRenamed: (group: Group) => void
  onBack: () => void
}

/** Renames one group and edits its direct members. */
export function GroupEditor({ group, onRenamed, onBack }: GroupEditorProps) {
  const [name, setName] = useState(group.name)
  const [error, setError] = useState<ApiError | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const unchanged = name.trim() === group.name

  async function rename(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setNotice(null)
    try {
      const renamed = await api.renameGroup(group.pk, name.trim())
      setName(renamed.name)
      setNotice(`Renamed to ${renamed.name}.`)
      onRenamed(renamed)
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, String(err)))
    } finally {
      setSaving(false)
    }
  }

  const nameErrors = error?.fields.name
  return (
    <>
      <DialogContent sx={{ pt: 0 }}>
        <Stack spacing={3} sx={{ pt: 1 }}>
          <Stack component="form" spacing={1} onSubmit={rename}>
            {error && !nameErrors?.length && <Alert severity="error">{error.message}</Alert>}
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
          <GroupMembers group={group} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onBack}>Back to groups</Button>
      </DialogActions>
    </>
  )
}
