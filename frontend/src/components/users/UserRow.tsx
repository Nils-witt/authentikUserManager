import Avatar from '@mui/material/Avatar'
import Chip from '@mui/material/Chip'
import Stack from '@mui/material/Stack'
import TableCell from '@mui/material/TableCell'
import TableRow from '@mui/material/TableRow'
import { UserRowActions, type UserRowActionsProps } from './UserRowActions'

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : '—'
}

/** One user in the user table; inactive users are greyed out. */
export function UserRow(props: UserRowActionsProps) {
  const { user } = props
  return (
    <TableRow hover sx={user.is_active ? undefined : { '& td': { color: 'text.disabled' } }}>
      <TableCell>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
          <Avatar src={user.avatar || undefined} alt="" sx={{ width: 24, height: 24 }} />
          <span>{user.username}</span>
          {user.is_superuser && <Chip size="small" variant="outlined" label="admin" />}
        </Stack>
      </TableCell>
      <TableCell>{user.name}</TableCell>
      <TableCell>{user.email || '—'}</TableCell>
      <TableCell sx={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis' }}>
        {(user.groups_obj ?? []).map((g) => g.name).join(', ') || '—'}
      </TableCell>
      <TableCell>
        <Chip
          size="small"
          color={user.is_active ? 'success' : 'default'}
          variant="outlined"
          label={user.is_active ? 'active' : 'inactive'}
        />
      </TableCell>
      <TableCell>{formatDate(user.last_login)}</TableCell>
      <TableCell align="right">
        <UserRowActions {...props} />
      </TableCell>
    </TableRow>
  )
}
