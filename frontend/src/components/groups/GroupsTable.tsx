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
import type { ReactNode } from 'react'
import type { Group, PublicGroup } from '../../api'

interface GroupsTableProps {
  /** The groups of the current page, or undefined before the first load. */
  groups: (PublicGroup | Group)[] | undefined
  loading: boolean
  /**
   * Called to edit a group. When set, the table shows the details access
   * administrators see, and an edit button for each group.
   */
  onEdit?: (group: Group) => void
  /** Renders the join controls of a group for users who are not access administrators. */
  renderJoin?: (group: PublicGroup) => ReactNode
}

/** Reports whether g carries the details access administrators see. */
const isAdminView = (g: PublicGroup | Group): g is Group => 'visible' in g

/** Lists authentik groups, with an edit button each for access administrators or join controls for everyone else. */
export function GroupsTable({ groups, loading, onEdit, renderJoin }: GroupsTableProps) {
  const columns = 2 + (onEdit ? 2 : 0) + (renderJoin ? 1 : 0)
  return (
    <TableContainer component={Paper} variant="outlined" aria-busy={loading}>
      <Box sx={{ height: 4 }}>{loading && <LinearProgress />}</Box>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Name</TableCell>
            <TableCell>Parent</TableCell>
            {onEdit && <TableCell>Visible to all</TableCell>}
            {onEdit && <TableCell aria-label="Actions" />}
            {renderJoin && <TableCell aria-label="Membership" />}
          </TableRow>
        </TableHead>
        <TableBody>
          {groups?.map((group) => (
            <TableRow key={group.pk} hover>
              <TableCell>
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <span>{group.name}</span>
                  {isAdminView(group) && group.is_superuser && (
                    <Chip size="small" variant="outlined" label="admin" />
                  )}
                </Stack>
              </TableCell>
              <TableCell>{group.parent_name || '—'}</TableCell>
              {onEdit && isAdminView(group) && (
                <>
                  <TableCell>{group.visible ? 'yes' : 'no'}</TableCell>
                  <TableCell align="right">
                    <Tooltip title="Edit">
                      <IconButton size="small" onClick={() => onEdit(group)}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </>
              )}
              {renderJoin && <TableCell align="right">{renderJoin(group)}</TableCell>}
            </TableRow>
          ))}
          {groups?.length === 0 && (
            <TableRow>
              <TableCell colSpan={columns} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                No groups found.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
