import Alert from '@mui/material/Alert'
import Autocomplete from '@mui/material/Autocomplete'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import FormControlLabel from '@mui/material/FormControlLabel'
import MenuItem from '@mui/material/MenuItem'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import { useState, type FormEvent } from 'react'
import { ApiError, type CreateUserInput, type User, type UserInput } from '../api'
import { Modal } from './Modal'

interface UserFormProps {
  /** The user being edited, or undefined to create a new one. */
  user?: User
  /** Path for a new user; defaults to "users". */
  defaultPath?: string
  /**
   * Groups the operator may add users to or remove them from; undefined means any group.
   * When set, a new user must join one of them.
   */
  groups?: string[]
  /** Group names suggested when any group may be chosen. */
  groupSuggestions?: string[]
  /** Receives the user's groups too; they are only edited for an existing user. */
  onSubmit: (input: CreateUserInput, groups: string[]) => Promise<void>
  onClose: () => void
}

export function UserForm({
  user,
  defaultPath,
  groups,
  groupSuggestions,
  onSubmit,
  onClose,
}: UserFormProps) {
  const [input, setInput] = useState<UserInput>({
    username: user?.username ?? '',
    name: user?.name ?? '',
    email: user?.email ?? '',
    is_active: user?.is_active ?? true,
    path: user?.path ?? defaultPath ?? 'users',
  })
  const [group, setGroup] = useState(groups?.length === 1 ? groups[0] : '')
  const [memberOf, setMemberOf] = useState(() => (user?.groups_obj ?? []).map((g) => g.name))
  // Groups outside the operator's scope stay as they are.
  const editable = (g: string) => !groups || groups.includes(g)
  const fixed = memberOf.filter((g) => !editable(g))
  const [error, setError] = useState<ApiError | null>(null)
  const [saving, setSaving] = useState(false)

  const set = <K extends keyof UserInput>(key: K, value: UserInput[K]) =>
    setInput((prev) => ({ ...prev, [key]: value }))

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      await onSubmit(!user && group ? { ...input, group } : input, memberOf)
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, String(err)))
    } finally {
      setSaving(false)
    }
  }

  /** Props showing the server's validation errors for a field. */
  const fieldError = (name: string) => {
    const msgs = error?.fields[name]
    return msgs?.length ? { error: true, helperText: msgs.join(' ') } : {}
  }

  return (
    <Modal title={user ? `Edit ${user.username}` : 'Create user'} onClose={onClose}>
      <form onSubmit={handleSubmit}>
        <DialogContent sx={{ pt: 0 }}>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {error && (
              <Alert severity="error">
                {error.message}
                {error.fields.non_field_errors?.map((msg) => (
                  <span key={msg}> {msg}</span>
                ))}
              </Alert>
            )}
            <TextField
              label="Username"
              required
              autoFocus
              value={input.username}
              onChange={(e) => set('username', e.target.value)}
              slotProps={{ htmlInput: { maxLength: 150 } }}
              {...fieldError('username')}
            />
            <TextField
              label="Display name"
              required
              value={input.name}
              onChange={(e) => set('name', e.target.value)}
              {...fieldError('name')}
            />
            <TextField
              label="Email"
              type="email"
              value={input.email}
              onChange={(e) => set('email', e.target.value)}
              slotProps={{ htmlInput: { maxLength: 254 } }}
              {...fieldError('email')}
            />
            <TextField
              label="Path"
              value={input.path}
              onChange={(e) => set('path', e.target.value)}
              {...fieldError('path')}
            />
            {!user && groups && (
              <TextField
                select
                label="Group"
                required
                value={group}
                onChange={(e) => setGroup(e.target.value)}
                {...fieldError('group')}
              >
                {groups.map((g) => (
                  <MenuItem key={g} value={g}>
                    {g}
                  </MenuItem>
                ))}
              </TextField>
            )}
            {user && (
              <Autocomplete
                multiple
                freeSolo={!groups}
                disableClearable
                options={(groups ?? groupSuggestions ?? []).filter((g) => !memberOf.includes(g))}
                value={memberOf}
                onChange={(_, value) =>
                  setMemberOf([
                    ...new Set([...fixed, ...value.map((v) => v.trim()).filter(Boolean)]),
                  ])
                }
                renderValue={(value, getItemProps) =>
                  value.map((g, index) => {
                    const { key, onDelete, ...itemProps } = getItemProps({ index })
                    return (
                      <Chip
                        key={key}
                        size="small"
                        label={g}
                        {...itemProps}
                        onDelete={editable(g) ? onDelete : undefined}
                      />
                    )
                  })
                }
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label="Groups"
                    placeholder={groups ? 'Add a group' : 'Group name, then Enter'}
                    {...fieldError('groups')}
                  />
                )}
              />
            )}
            <FormControlLabel
              label="Active"
              control={
                <Switch
                  checked={input.is_active}
                  onChange={(e) => set('is_active', e.target.checked)}
                />
              }
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="contained" loading={saving}>
            {user ? 'Save' : 'Create'}
          </Button>
        </DialogActions>
      </form>
    </Modal>
  )
}
