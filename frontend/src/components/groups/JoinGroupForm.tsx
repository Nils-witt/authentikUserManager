import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState, type FormEvent } from 'react'
import * as api from '../../api'
import { ApiError, type PublicGroup } from '../../api'

/** Matches joinrequest.MaxMessageLen on the server. */
const MAX_MESSAGE_LENGTH = 500

interface JoinGroupFormProps {
  group: PublicGroup
  /** Called once the request was sent. */
  onRequested: () => void
  onBack: () => void
}

/** Asks to join a visible group, with an optional message for the operators deciding. */
export function JoinGroupForm({ group, onRequested, onBack }: JoinGroupFormProps) {
  const [message, setMessage] = useState('')
  const [error, setError] = useState<ApiError | null>(null)
  const [saving, setSaving] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      await api.requestJoin(group.pk, message.trim())
      onRequested()
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, String(err)))
      setSaving(false)
    }
  }

  const messageErrors = error?.fields.message
  return (
    <form onSubmit={submit}>
      <DialogContent sx={{ pt: 0 }}>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && !messageErrors?.length && <Alert severity="error">{error.message}</Alert>}
          <Typography variant="body2" color="text.secondary">
            The operators who manage {group.name} decide your request. You join the group once they
            approve it.
          </Typography>
          <TextField
            label="Message (optional)"
            placeholder="Why do you want to join?"
            multiline
            minRows={3}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            error={Boolean(messageErrors?.length)}
            helperText={messageErrors?.join(' ') ?? `${message.length}/${MAX_MESSAGE_LENGTH}`}
            slotProps={{ htmlInput: { maxLength: MAX_MESSAGE_LENGTH } }}
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onBack}>Back to groups</Button>
        <Button type="submit" variant="contained" loading={saving}>
          Send request
        </Button>
      </DialogActions>
    </form>
  )
}
