import BlockIcon from '@mui/icons-material/Block'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import DeleteIcon from '@mui/icons-material/Delete'
import EditIcon from '@mui/icons-material/Edit'
import LockIcon from '@mui/icons-material/Lock'
import MailLockIcon from '@mui/icons-material/MailLock'
import IconButton from '@mui/material/IconButton'
import Tooltip from '@mui/material/Tooltip'
import type { User } from '../../api'

export interface UserRowActionsProps {
  user: User
  /** Show the button sending a password recovery email. */
  canSendRecovery: boolean
  /** Show the delete button. */
  canDelete: boolean
  onEdit: (user: User) => void
  onToggleActive: (user: User) => void
  onSendRecovery: (user: User) => void
  onDelete: (user: User) => void
}

/** Icon buttons acting on a single user, or a lock when the operator may not change them. */
export function UserRowActions({
  user,
  canSendRecovery,
  canDelete,
  onEdit,
  onToggleActive,
  onSendRecovery,
  onDelete,
}: UserRowActionsProps) {
  if (!user.changeable) {
    return (
      <Tooltip
        title={
          user.primary_group
            ? `Only the operators managing the primary group "${user.primary_group}" can change this user`
            : // Without a primary group, only an own account outside the operator's scope is locked.
              'You can see your own account but not change it'
        }
      >
        <LockIcon fontSize="small" color="disabled" sx={{ verticalAlign: 'middle' }} />
      </Tooltip>
    )
  }
  return (
    <>
      <Tooltip title="Edit">
        <IconButton size="small" onClick={() => onEdit(user)}>
          <EditIcon fontSize="small" />
        </IconButton>
      </Tooltip>
      <Tooltip title={user.is_active ? 'Deactivate' : 'Activate'}>
        <IconButton size="small" onClick={() => onToggleActive(user)}>
          {user.is_active ? <BlockIcon fontSize="small" /> : <CheckCircleIcon fontSize="small" />}
        </IconButton>
      </Tooltip>
      {canSendRecovery && (
        <Tooltip title={user.email ? 'Send recovery email' : 'No email address'}>
          <span>
            <IconButton size="small" disabled={!user.email} onClick={() => onSendRecovery(user)}>
              <MailLockIcon fontSize="small" />
            </IconButton>
          </span>
        </Tooltip>
      )}
      {canDelete && (
        <Tooltip title="Delete">
          <IconButton size="small" color="error" onClick={() => onDelete(user)}>
            <DeleteIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      )}
    </>
  )
}
