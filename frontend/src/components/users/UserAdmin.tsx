import Box from '@mui/material/Box'
import Container from '@mui/material/Container'
import { useState } from 'react'
import * as api from '../../api'
import type { Me, User } from '../../api'
import { errorMessage } from '../../errors'
import { useAccess } from '../../hooks/useAccess'
import { useConfirm } from '../../hooks/useConfirm'
import { useGroupNames } from '../../hooks/useGroupNames'
import { useUserFilters } from '../../hooks/useUserFilters'
import { useUserList } from '../../hooks/useUserList'
import { useUserPaths } from '../../hooks/useUserPaths'
import { NoticeSnackbar } from '../common/NoticeSnackbar'
import { FolderTree } from '../folders/FolderTree'
import { AppHeader } from '../layout/AppHeader'
import { StatusAlerts } from './StatusAlerts'
import { UserDialog, type UserDialogState } from './UserDialog'
import { UserPagination } from './UserPagination'
import { UserTable } from './UserTable'
import { UserToolbar } from './UserToolbar'

/** The user list with its filters, actions and dialogs. */
export function UserAdmin({ me }: { me: Me }) {
  const [confirm, confirmDialog] = useConfirm()
  const filters = useUserFilters()
  // Bumped after every mutation to refetch the users, folders and access.
  const [version, setVersion] = useState(0)
  const { data, loading, error: listError } = useUserList(filters, version)
  const { paths, error: pathsError } = useUserPaths(version)
  const { access, noAccess, error: accessError } = useAccess(version)
  const isAdmin = access?.admin ?? false
  // Suggestions for a user's groups; only access administrators may list every group.
  const groupNames = useGroupNames(isAdmin)
  const [actionError, setActionError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dialog, setDialog] = useState<UserDialogState>(null)

  const refresh = () => setVersion((v) => v + 1)

  const done = (message: string) => {
    setDialog(null)
    setNotice(message)
    setActionError(null)
    refresh()
  }

  /** Runs a user action, reporting a failure above the table. */
  async function run(action: () => Promise<void>) {
    try {
      await action()
    } catch (err) {
      setActionError(errorMessage(err))
    }
  }

  const toggleActive = (user: User) =>
    run(async () => {
      await api.updateUser(user.pk, { is_active: !user.is_active })
      done(`${user.username} ${user.is_active ? 'deactivated' : 'activated'}.`)
    })

  async function sendRecovery(user: User) {
    const ok = await confirm({
      title: `Send recovery email to ${user.username}?`,
      message: `${user.email} receives a link to set a new password.`,
      confirmLabel: 'Send',
      color: 'primary',
    })
    if (!ok) return
    await run(async () => {
      await api.sendRecoveryEmail(user.pk)
      done(`Recovery email sent to ${user.email}.`)
    })
  }

  async function remove(user: User) {
    const ok = await confirm({
      title: `Delete ${user.username}?`,
      message: 'The user is removed from authentik. This cannot be undone.',
      confirmLabel: 'Delete',
    })
    if (!ok) return
    await run(async () => {
      await api.deleteUser(user.pk)
      done(`${user.username} deleted.`)
    })
  }

  return (
    <>
      <AppHeader me={me} />

      <Container component="main" maxWidth="xl" sx={{ py: 3 }}>
        <UserToolbar
          search={filters.search}
          onSearchChange={filters.setSearch}
          status={filters.status}
          onStatusChange={filters.selectStatus}
          onOpenRules={isAdmin ? () => setDialog({ kind: 'rules' }) : undefined}
          onOpenAudit={isAdmin ? () => setDialog({ kind: 'audit' }) : undefined}
          onCreate={access && !noAccess ? () => setDialog({ kind: 'create' }) : undefined}
        />

        <StatusAlerts
          errors={[actionError, listError, pathsError, accessError]}
          access={access}
          noAccess={noAccess}
        />

        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: { xs: 'minmax(0, 1fr)', md: '240px minmax(0, 1fr)' },
            gap: 2,
            alignItems: 'start',
          }}
        >
          <FolderTree paths={paths} selected={filters.folder} onSelect={filters.selectFolder} />
          <Box component="section">
            <UserTable
              users={data?.results}
              loading={loading}
              canSendRecovery={access?.recovery_email ?? false}
              canDelete={isAdmin}
              onEdit={(user) => setDialog({ kind: 'edit', user })}
              onToggleActive={(user) => void toggleActive(user)}
              onSendRecovery={(user) => void sendRecovery(user)}
              onDelete={(user) => void remove(user)}
            />
            <UserPagination
              pagination={data?.pagination}
              page={filters.page}
              onChange={filters.setPage}
            />
          </Box>
        </Box>
      </Container>

      <NoticeSnackbar notice={notice} onClose={() => setNotice(null)} />
      {confirmDialog}

      <UserDialog
        dialog={dialog}
        access={access}
        folder={filters.folder}
        groupSuggestions={groupNames}
        onClose={() => setDialog(null)}
        onDone={done}
        onRulesClose={() => {
          setDialog(null)
          refresh()
        }}
      />
    </>
  )
}
