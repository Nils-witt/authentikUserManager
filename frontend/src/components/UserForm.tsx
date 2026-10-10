import { useState, type FormEvent } from 'react'
import { ApiError, USER_TYPES, type User, type UserInput, type UserType } from '../api'
import { Modal } from './Modal'

interface UserFormProps {
  /** The user being edited, or undefined to create a new one. */
  user?: User
  /** Path for a new user; defaults to "users". */
  defaultPath?: string
  onSubmit: (input: UserInput) => Promise<void>
  onClose: () => void
}

export function UserForm({ user, defaultPath, onSubmit, onClose }: UserFormProps) {
  const [input, setInput] = useState<UserInput>({
    username: user?.username ?? '',
    name: user?.name ?? '',
    email: user?.email ?? '',
    is_active: user?.is_active ?? true,
    path: user?.path ?? defaultPath ?? 'users',
    type: user?.type ?? 'internal',
  })
  const [error, setError] = useState<ApiError | null>(null)
  const [saving, setSaving] = useState(false)

  const set = <K extends keyof UserInput>(key: K, value: UserInput[K]) =>
    setInput((prev) => ({ ...prev, [key]: value }))

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      await onSubmit(input)
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, String(err)))
    } finally {
      setSaving(false)
    }
  }

  const fieldError = (name: string) =>
    error?.fields[name]?.map((msg) => (
      <span key={msg} className="field-error">
        {msg}
      </span>
    ))

  return (
    <Modal title={user ? `Edit ${user.username}` : 'Create user'} onClose={onClose}>
      <form onSubmit={handleSubmit} className="form">
        {error && (
          <p className="alert" role="alert">
            {error.message}
            {error.fields.non_field_errors?.map((msg) => <span key={msg}> {msg}</span>)}
          </p>
        )}
        <label>
          Username
          <input
            required
            maxLength={150}
            value={input.username}
            onChange={(e) => set('username', e.target.value)}
          />
          {fieldError('username')}
        </label>
        <label>
          Display name
          <input required value={input.name} onChange={(e) => set('name', e.target.value)} />
          {fieldError('name')}
        </label>
        <label>
          Email
          <input
            type="email"
            maxLength={254}
            value={input.email}
            onChange={(e) => set('email', e.target.value)}
          />
          {fieldError('email')}
        </label>
        <label>
          Path
          <input value={input.path} onChange={(e) => set('path', e.target.value)} />
          {fieldError('path')}
        </label>
        <label>
          Type
          <select value={input.type} onChange={(e) => set('type', e.target.value as UserType)}>
            {USER_TYPES.map((t) => (
              <option key={t} value={t}>
                {t.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
          {fieldError('type')}
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={input.is_active}
            onChange={(e) => set('is_active', e.target.checked)}
          />
          Active
        </label>
        <footer className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={saving}>
            {saving ? 'Saving…' : user ? 'Save' : 'Create'}
          </button>
        </footer>
      </form>
    </Modal>
  )
}
