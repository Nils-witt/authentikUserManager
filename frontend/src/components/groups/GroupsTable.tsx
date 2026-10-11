import EditIcon from '@mui/icons-material/Edit'
import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import IconButton from '@mui/material/IconButton'
import LinearProgress from '@mui/material/LinearProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Tooltip from '@mui/material/Tooltip'
import type { Group } from '../../api'

interface GroupsTableProps {
  /** The groups of the current page, or undefined before the first load. */
  groups: Group[] | undefined
  loading: boolean
  onEdit: (group: Group) => void
}

/** Lists authentik groups with an edit button each. */
export function GroupsTable({ groups, loading, onEdit }: GroupsTableProps) {
  return (
    <TableContainer component={Paper} variant="outlined" aria-busy={loading}>
      <Box sx={{ height: 4 }}>{loading && <LinearProgress />}</Box>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Name</TableCell>
            <TableCell>Parent</TableCell>
            <TableCell aria-label="Actions" />
          </TableRow>
        </TableHead>
        <TableBody>
          {groups?.map((group) => (
            <TableRow key={group.pk} hover>
              <TableCell>
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <span>{group.name}</span>
                  {group.is_superuser && <Chip size="small" variant="outlined" label="admin" />}
                </Stack>
              </TableCell>
              <TableCell>{group.parent_name || '—'}</TableCell>
              <TableCell align="right">
                <Tooltip title="Edit">
                  <IconButton size="small" onClick={() => onEdit(group)}>
                    <EditIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              </TableCell>
            </TableRow>
          ))}
          {groups?.length === 0 && (
            <TableRow>
              <TableCell colSpan={3} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                No groups found.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
