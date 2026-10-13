import AppsIcon from '@mui/icons-material/Apps'
import BlockIcon from '@mui/icons-material/Block'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import DeleteIcon from '@mui/icons-material/Delete'
import EditIcon from '@mui/icons-material/Edit'
import KeyIcon from '@mui/icons-material/Key'
import LockIcon from '@mui/icons-material/Lock'
import MailLockIcon from '@mui/icons-material/MailLock'
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'
import IconButton from '@mui/material/IconButton'
import Tooltip from '@mui/material/Tooltip'
import type { User } from '../../api'

export interface UserRowActionsProps {
  user: User
  /** Show the button sending a password recovery email. */
  canSendRecovery: boolean
  /** Show the button listing the user's certificates. */
  canManageCertificates: boolean
  /** Show the delete button. */
  canDelete: boolean
  onEdit: (user: User) => void
  onToggleActive: (user: User) => void
  onSendRecovery: (user: User) => void
  onCertificates: (user: User) => void
  onDelete: (user: User) => void
  /** Lists the tokens of a service account; the button is hidden when undefined. */
  onTokens?: (user: User) => void
  /** Lists the applications the user may access; the button is hidden when undefined. */
  onApplications?: (user: User) => void
}

/** Icon buttons acting on a single user, or a lock when the operator may not change them. */
export function UserRowActions({
  user,
  canSendRecovery,
  canManageCertificates,
  canDelete,
  onEdit,
  onToggleActive,
  onSendRecovery,
  onCertificates,
  onDelete,
  onTokens,
  onApplications,
}: UserRowActionsProps) {
  // Listing the applications changes nothing, so it is offered for locked users too.
  const applicationsButton = onApplications && (
    <Tooltip title="Applications">
      <IconButton size="small" onClick={() => onApplications(user)}>
        <AppsIcon fontSize="small" />
      </IconButton>
    </Tooltip>
  )
  if (!user.changeable) {
    return (
      <>
        {applicationsButton}
        <Tooltip
          title={
            user.primary_group
              ? `Only the operators managing the primary group "${user.primary_group}" can change this account`
              : // Without a primary group, only an own account outside the operator's scope is locked.
                'You can see your own account but not change it'
          }
        >
          <LockIcon fontSize="small" color="disabled" sx={{ verticalAlign: 'middle' }} />
        </Tooltip>
      </>
    )
  }
  return (
    <>
      {applicationsButton}
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
      {onTokens && (
        <Tooltip title="Tokens">
          <IconButton size="small" onClick={() => onTokens(user)}>
            <KeyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      )}
      {canManageCertificates && (
        <Tooltip title="Certificates">
          <IconButton size="small" onClick={() => onCertificates(user)}>
            <VerifiedUserIcon fontSize="small" />
          </IconButton>
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
