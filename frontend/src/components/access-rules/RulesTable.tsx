import DeleteIcon from '@mui/icons-material/Delete'
import EditIcon from '@mui/icons-material/Edit'
import Chip from '@mui/material/Chip'
import IconButton from '@mui/material/IconButton'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Tooltip from '@mui/material/Tooltip'
import { WILDCARD, type AccessRule } from '../../api'

interface RulesTableProps {
  /** The rules, or null while they load. */
  rules: AccessRule[] | null
  onEdit: (rule: AccessRule) => void
  onRemove: (rule: AccessRule) => void
}

/** Lists the access rules with edit and remove buttons. */
export function RulesTable({ rules, onEdit, onRemove }: RulesTableProps) {
  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Operator group</TableCell>
            <TableCell>May manage members of</TableCell>
            <TableCell aria-label="Actions" />
          </TableRow>
        </TableHead>
        <TableBody>
          {rules?.map((rule) => (
            <TableRow key={rule.operator_group}>
              <TableCell>{rule.operator_group}</TableCell>
              <TableCell sx={{ whiteSpace: 'normal' }}>
                <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
                  {rule.target_groups.map((t) => (
                    <Chip key={t} size="small" label={t === WILDCARD ? 'all users' : t} />
                  ))}
                </Stack>
              </TableCell>
              <TableCell align="right">
                <Tooltip title="Edit">
                  <IconButton size="small" onClick={() => onEdit(rule)}>
                    <EditIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Remove">
                  <IconButton size="small" color="error" onClick={() => onRemove(rule)}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              </TableCell>
            </TableRow>
          ))}
          {rules?.length === 0 && (
            <TableRow>
              <TableCell colSpan={3} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                No rules yet. Only access administrators can manage users.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
