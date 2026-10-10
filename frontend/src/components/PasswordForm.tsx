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
      <form onSubmit={handleSubmit} className="form">
        {error && (
          <p className="alert" role="alert">
            {error}
          </p>
        )}
        <label>
          New password
          <input
            type="password"
            required
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <label>
          Confirm password
          <input
            type="password"
            required
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </label>
        <footer className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={saving}>
            {saving ? 'Saving…' : 'Set password'}
          </button>
        </footer>
      </form>
    </Modal>
  )
}
