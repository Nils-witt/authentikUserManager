import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import FormControlLabel from '@mui/material/FormControlLabel'
import MenuItem from '@mui/material/MenuItem'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import { useState, type FormEvent } from 'react'
import { ApiError, type CreateUserInput, type User, type UserInput } from '../../api'
import { Modal } from '../common/Modal'
import { UserGroupsField } from './UserGroupsField'

interface UserFormProps {
  /** The user being edited, or undefined to create a new one. */
  user?: User
  /** What the account is called in the dialog; defaults to "user". */
  noun?: string
  /** Path for a new user; defaults to "users". */
  defaultPath?: string
  /**
   * Groups the operator may add users to or remove them from; undefined means any group.
   * When set, a new user must join one of them.
   */
  groups?: string[]
  /** Group names suggested when any group may be chosen. */
  groupSuggestions?: string[]
  /** The operator may hide the user from operators who are not access administrators. */
  canHide?: boolean
  /**
   * Receives the user's groups and the name of their primary group ('' for none) too; they are only
   * edited for an existing user.
   */
  onSubmit: (input: CreateUserInput, groups: string[], primaryGroup: string) => Promise<void>
  onClose: () => void
}

/** Dialog creating a user, or editing one including their groups. */
export function UserForm({
  user,
  noun = 'user',
  defaultPath,
  groups,
  groupSuggestions,
  canHide = false,
  onSubmit,
  onClose,
}: UserFormProps) {
  const [input, setInput] = useState<UserInput>({
    username: user?.username ?? '',
    name: user?.name ?? '',
    email: user?.email ?? '',
    is_active: user?.is_active ?? true,
    path: user?.path ?? defaultPath ?? 'users',
    // Only sent when the operator may change it.
    ...(canHide ? { hidden: user?.hidden ?? false } : {}),
  })
  const [group, setGroup] = useState(groups?.length === 1 ? groups[0] : '')
  const [memberOf, setMemberOf] = useState(() => (user?.groups_obj ?? []).map((g) => g.name))
  const [primary, setPrimary] = useState(user?.primary_group ?? '')
  const [error, setError] = useState<ApiError | null>(null)
  const [saving, setSaving] = useState(false)

  const set = <K extends keyof UserInput>(key: K, value: UserInput[K]) =>
    setInput((prev) => ({ ...prev, [key]: value }))

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      await onSubmit(!user && group ? { ...input, group } : input, memberOf, primary)
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, String(err)))
    } finally {
      setSaving(false)
    }
  }

  const editable = (g: string) => !groups || groups.includes(g)
  // Restricted operators may only choose, change or remove primary groups they manage.
  const primaryEditable = primary === '' || editable(primary)
  const primaryOptions = memberOf.filter((g) => g === primary || editable(g))

  /** Props showing the server's validation errors for a field. */
  const fieldError = (name: string) => {
    const msgs = error?.fields[name]
    return msgs?.length ? { error: true, helperText: msgs.join(' ') } : {}
  }

  return (
    <Modal title={user ? `Edit ${user.username}` : `Create ${noun}`} onClose={onClose}>
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
                helperText={`Also becomes the ${noun}'s primary group.`}
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
              <UserGroupsField
                value={memberOf}
                onChange={setMemberOf}
                groups={groups}
                suggestions={groupSuggestions}
                primary={primary}
                errorProps={fieldError('groups')}
              />
            )}
            {user && (
              <TextField
                select
                label="Primary group"
                value={primary}
                onChange={(e) => setPrimary(e.target.value)}
                disabled={!primaryEditable}
                helperText="Choose another primary group before removing this one from the groups."
                {...fieldError('primary_group')}
              >
                <MenuItem value="">
                  <em>None</em>
                </MenuItem>
                {primaryOptions.map((g) => (
                  <MenuItem key={g} value={g}>
                    {g}
                  </MenuItem>
                ))}
              </TextField>
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
            {canHide && (
              <FormControlLabel
                label="Hidden from operators who are not access administrators"
                control={
                  <Switch
                    checked={input.hidden ?? false}
                    onChange={(e) => set('hidden', e.target.checked)}
                  />
                }
              />
            )}
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
