import Box from '@mui/material/Box'
import LinearProgress from '@mui/material/LinearProgress'
import Paper from '@mui/material/Paper'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import type { User } from '../../api'
import { UserRow } from './UserRow'
import type { UserRowActionsProps } from './UserRowActions'

interface UserTableProps extends Omit<UserRowActionsProps, 'user'> {
  /** The users of the current page, or undefined before the first load. */
  users: User[] | undefined
  loading: boolean
  /** What the listed accounts are called; defaults to "user". */
  noun?: string
}

/** Table of users with per-row actions. */
export function UserTable({ users, loading, noun = 'user', ...actions }: UserTableProps) {
  return (
    <TableContainer component={Paper} variant="outlined" aria-busy={loading}>
      <Box sx={{ height: 4 }}>{loading && <LinearProgress />}</Box>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Username</TableCell>
            <TableCell>Name</TableCell>
            <TableCell>Email</TableCell>
            <TableCell>Groups</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Last login</TableCell>
            <TableCell aria-label="Actions" />
          </TableRow>
        </TableHead>
        <TableBody>
          {users?.map((user) => (
            <UserRow key={user.pk} user={user} {...actions} />
          ))}
          {users?.length === 0 && (
            <TableRow>
              <TableCell colSpan={7} align="center" sx={{ color: 'text.secondary', py: 4 }}>
                No {noun}s found.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
