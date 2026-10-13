import Box from '@mui/material/Box'
import Container from '@mui/material/Container'
import { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router'
import * as api from '../../api'
import type { User } from '../../api'
import { errorMessage } from '../../errors'
import { useAppContext } from '../../hooks/useAppContext'
import { useConfirm } from '../../hooks/useConfirm'
import { useGroupNames } from '../../hooks/useGroupNames'
import { useUserFilters } from '../../hooks/useUserFilters'
import { useUserList } from '../../hooks/useUserList'
import { useUserPaths } from '../../hooks/useUserPaths'
import { dialogForPath, dialogPaths, pagePaths, type RoutedDialog } from '../../paths'
import { ListPagination } from '../common/ListPagination'
import { NoticeSnackbar } from '../common/NoticeSnackbar'
import { FolderTree } from '../folders/FolderTree'
import { ApplicationsDialog } from './ApplicationsDialog'
import { CertificatesDialog } from './CertificatesDialog'
import { StatusAlerts } from './StatusAlerts'
import { UserDialog, type UserDialogState } from './UserDialog'
import { UserTable } from './UserTable'
import { UserToolbar } from './UserToolbar'

/** The user list with its filters, actions and dialogs. */
export function UserAdmin() {
  const [confirm, confirmDialog] = useConfirm()
  const filters = useUserFilters()
  // The version is bumped after every mutation to refetch the users, folders and access.
  const { access, noAccess, accessError, version, refresh } = useAppContext()
  const { data, loading, error: listError } = useUserList(filters, version)
  const { paths, error: pathsError } = useUserPaths(version)
  const isAdmin = access?.admin ?? false
  // Suggestions for a user's groups; only access administrators may list every group.
  const groupNames = useGroupNames(isAdmin)
  const [actionError, setActionError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  // Editing needs the user object, so it is kept in state; the other dialogs have a URL.
  const [editing, setEditing] = useState<User | null>(null)
  // The user whose certificates are listed, if any.
  const [certificatesOf, setCertificatesOf] = useState<User | null>(null)
  // The user whose applications are listed, if any.
  const [applicationsOf, setApplicationsOf] = useState<User | null>(null)
  const navigate = useNavigate()
  const { pathname, search } = useLocation()
  const routed = dialogForPath(pathname)
  // The dialogs keep the list's filters in the query.
  const go = (path: string) => void navigate({ pathname: path, search })
  const allowed: Record<RoutedDialog, boolean> = {
    create: access !== null && !noAccess,
  }
  const dialog: UserDialogState = editing
    ? { kind: 'edit', user: editing }
    : routed && allowed[routed]
      ? { kind: routed }
      : null

  const closeDialog = () => {
    setEditing(null)
    if (routed) go(pagePaths.users)
  }

  const done = (message: string) => {
    closeDialog()
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
      <Container component="main" maxWidth="xl" sx={{ py: 3 }}>
        <UserToolbar
          search={filters.search}
          onSearchChange={filters.setSearch}
          status={filters.status}
          onStatusChange={filters.selectStatus}
          onCreate={allowed.create ? () => go(dialogPaths.create) : undefined}
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
              canManageCertificates={access?.certificates ?? false}
              canDelete={isAdmin}
              onEdit={setEditing}
              onToggleActive={(user) => void toggleActive(user)}
              onSendRecovery={(user) => void sendRecovery(user)}
              onCertificates={setCertificatesOf}
              onApplications={setApplicationsOf}
              onDelete={(user) => void remove(user)}
            />
            <ListPagination
              pagination={data?.pagination}
              page={filters.page}
              onChange={filters.setPage}
              noun="users"
            />
          </Box>
        </Box>
      </Container>

      {/* A dialog the operator may not open closes again. */}
      {routed && access && !allowed[routed] && (
        <Navigate to={{ pathname: pagePaths.users, search }} replace />
      )}

      <NoticeSnackbar notice={notice} onClose={() => setNotice(null)} />
      {confirmDialog}

      {certificatesOf && (
        <CertificatesDialog
          user={certificatesOf}
          onClose={() => setCertificatesOf(null)}
          onRevoked={setNotice}
        />
      )}

      {applicationsOf && (
        <ApplicationsDialog user={applicationsOf} onClose={() => setApplicationsOf(null)} />
      )}

      <UserDialog
        dialog={dialog}
        access={access}
        folder={filters.folder}
        groupSuggestions={groupNames}
        onClose={closeDialog}
        onDone={done}
      />
    </>
  )
}
