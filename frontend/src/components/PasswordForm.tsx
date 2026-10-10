import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import { useState, type FormEvent } from 'react'
import { ApiError, type User } from '../api'
import { Modal } from './Modal'

interface PasswordFormProps {
  user: User
  onSubmit: (password: string) => Promise<void>
  onClose: () => void
}

export function PasswordForm({ user, onSubmit, onClose }: PasswordFormProps) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }
    setSaving(true)
    setError(null)
    try {
      await onSubmit(password)
    } catch (err) {
      const msgs = err instanceof ApiError ? Object.values(err.fields).flat() : []
      setError([err instanceof Error ? err.message : String(err), ...msgs].join(' '))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title={`Set password for ${user.username}`} onClose={onClose}>
      <form onSubmit={handleSubmit}>
        <DialogContent sx={{ pt: 0 }}>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {error && <Alert severity="error">{error}</Alert>}
            <TextField
              label="New password"
              type="password"
              required
              autoFocus
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <TextField
              label="Confirm password"
              type="password"
              required
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="contained" loading={saving}>
            Set password
          </Button>
        </DialogActions>
      </form>
    </Modal>
  )
}
