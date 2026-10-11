import * as api from '../../api'
import type { Access, User } from '../../api'
import { AccessRules } from '../access-rules/AccessRules'
import { AuditLog } from '../audit/AuditLog'
import { UserForm } from './UserForm'

/** The dialog open on the user admin page, if any. */
export type UserDialogState =
  { kind: 'create' } | { kind: 'edit'; user: User } | { kind: 'rules' } | { kind: 'audit' } | null

interface UserDialogProps {
  dialog: UserDialogState
  access: Access | null
  /** Folder a new user is created in by default. */
  folder: string | null
  /** Group names suggested when editing a user's groups. */
  groupSuggestions: string[]
  onClose: () => void
  /** Called with a notice once a user was created or saved. */
  onDone: (message: string) => void
  /** Called when the access rules are closed; changes to them may have changed the operator's access. */
  onAdminClose: () => void
}

/** Renders the open dialog and saves its changes. */
export function UserDialog({
  dialog,
  access,
  folder,
  groupSuggestions,
  onClose,
  onDone,
  onAdminClose,
}: UserDialogProps) {
  // Restricted operators may only use the groups they manage.
  const groups = access && !access.all ? access.groups : undefined

  switch (dialog?.kind) {
    case 'create':
      return (
        <UserForm
          defaultPath={folder ?? undefined}
          groups={groups}
          onClose={onClose}
          onSubmit={async (input) => {
            const user = await api.createUser(input)
            onDone(`${user.username} created.`)
          }}
        />
      )
    case 'edit': {
      const { user } = dialog
      return (
        <UserForm
          user={user}
          groups={groups}
          groupSuggestions={groupSuggestions}
          onClose={onClose}
          onSubmit={async (input, memberOf, primaryGroup) => {
            // Groups first: they are the likelier to be rejected, and then nothing has changed yet.
            const before = (user.groups_obj ?? []).map((g) => g.name)
            const groupsChanged =
              before.length !== memberOf.length || before.some((g) => !memberOf.includes(g))
            const primaryChanged = primaryGroup !== user.primary_group
            if (groupsChanged || primaryChanged) {
              await api.setUserGroups(user.pk, memberOf, primaryChanged ? primaryGroup : undefined)
            }
            await api.updateUser(user.pk, input)
            onDone(`${input.username} saved.`)
          }}
        />
      )
    }
    case 'rules':
      return <AccessRules onClose={onAdminClose} />
    case 'audit':
      return <AuditLog onClose={onClose} />
    default:
      return null
  }
}
