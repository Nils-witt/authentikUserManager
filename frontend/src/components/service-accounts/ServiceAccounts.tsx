import Box from '@mui/material/Box'
import Container from '@mui/material/Container'
import DialogContent from '@mui/material/DialogContent'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import * as api from '../../api'
import type { User } from '../../api'
import { errorMessage } from '../../errors'
import { useAppContext } from '../../hooks/useAppContext'
import { useConfirm } from '../../hooks/useConfirm'
import { useGroupNames } from '../../hooks/useGroupNames'
import { useUserFilters } from '../../hooks/useUserFilters'
import { useUserList } from '../../hooks/useUserList'
import { useUserPaths } from '../../hooks/useUserPaths'
import { CertificateManager } from '../certificates/CertificateManager'
import { ListPagination } from '../common/ListPagination'
import { Modal } from '../common/Modal'
import { NoticeSnackbar } from '../common/NoticeSnackbar'
import { FolderTree } from '../folders/FolderTree'
import { StatusAlerts } from '../users/StatusAlerts'
import { UserForm } from '../users/UserForm'
import { UserTable } from '../users/UserTable'
import { UserToolbar } from '../users/UserToolbar'
import { ApiKeysDialog } from './ApiKeysDialog'
import { TokensDialog } from './TokensDialog'

const NOUN = 'service account'

/** The dialog open on the page, if any. */
type Dialog =
  | { kind: 'create' }
  | { kind: 'edit'; account: User }
  | { kind: 'tokens'; account: User }
  | { kind: 'api-keys'; account: User }
  | { kind: 'certificates'; account: User }
  | null

/**
 * The service accounts the operator may see, with their tokens and certificates. They follow the
 * same access rules and primary groups as users.
 */
export function ServiceAccounts() {
  const [confirm, confirmDialog] = useConfirm()
  const filters = useUserFilters()
  const { access, noAccess, accessError, version, refresh } = useAppContext()
  const { data, loading, error: listError } = useUserList(filters, version, api.listServiceAccounts)
  const { paths, error: pathsError } = useUserPaths(version, api.listServiceAccountPaths)
  const isAdmin = access?.admin ?? false
  const groupNames = useGroupNames(isAdmin)
  // Restricted operators may only use the groups they manage.
  const groups = access && !access.all ? access.groups : undefined
  const [dialog, setDialog] = useState<Dialog>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const done = (message: string) => {
    setDialog(null)
    setNotice(message)
    setActionError(null)
    refresh()
  }

  /** Runs an action, reporting a failure above the table. */
  async function run(action: () => Promise<void>) {
    try {
      await action()
    } catch (err) {
      setActionError(errorMessage(err))
    }
  }

  async function toggleActive(account: User) {
    if (account.is_active) {
      const ok = await confirm({
        title: `Deactivate ${account.username}?`,
        message: 'Its tokens stop working and its certificates are revoked.',
        confirmLabel: 'Deactivate',
      })
      if (!ok) return
    }
    await run(async () => {
      await api.updateServiceAccount(account.pk, { is_active: !account.is_active })
      done(`${account.username} ${account.is_active ? 'deactivated' : 'activated'}.`)
    })
  }

  async function remove(account: User) {
    const ok = await confirm({
      title: `Delete ${account.username}?`,
      message:
        'The service account and its tokens are removed from authentik, and its certificates are revoked. This cannot be undone.',
      confirmLabel: 'Delete',
    })
    if (!ok) return
    await run(async () => {
      await api.deleteServiceAccount(account.pk)
      done(`${account.username} deleted.`)
    })
  }

  return (
    <>
      <Container component="main" maxWidth="xl" sx={{ py: 3 }}>
        <Typography variant="h5" component="h2" sx={{ mb: 2 }}>
          Service accounts
        </Typography>
        <UserToolbar
          noun={NOUN}
          search={filters.search}
          onSearchChange={filters.setSearch}
          status={filters.status}
          onStatusChange={filters.selectStatus}
          onCreate={access !== null && !noAccess ? () => setDialog({ kind: 'create' }) : undefined}
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
          <FolderTree
            paths={paths}
            selected={filters.folder}
            onSelect={filters.selectFolder}
            noun={`${NOUN}s`}
          />
          <Box component="section">
            <UserTable
              noun={NOUN}
              users={data?.results}
              loading={loading}
              canSendRecovery={false}
              canManageCertificates={access?.certificates ?? false}
              canDelete={isAdmin}
              onEdit={(account) => setDialog({ kind: 'edit', account })}
              onToggleActive={(account) => void toggleActive(account)}
              onSendRecovery={() => undefined}
              onTokens={(account) => setDialog({ kind: 'tokens', account })}
              onApiKeys={(account) => setDialog({ kind: 'api-keys', account })}
              onCertificates={(account) => setDialog({ kind: 'certificates', account })}
              onDelete={(account) => void remove(account)}
            />
            <ListPagination
              pagination={data?.pagination}
              page={filters.page}
              onChange={filters.setPage}
              noun={`${NOUN}s`}
            />
          </Box>
        </Box>
      </Container>

      <NoticeSnackbar notice={notice} onClose={() => setNotice(null)} />
      {confirmDialog}

      {dialog?.kind === 'create' && (
        <UserForm
          noun={NOUN}
          defaultPath={filters.folder ?? 'service-accounts'}
          groups={groups}
          canHide={isAdmin}
          onClose={() => setDialog(null)}
          onSubmit={async (input) => {
            const account = await api.createServiceAccount(input)
            done(`${account.username} created. Create a token or certificate for it next.`)
          }}
        />
      )}
      {dialog?.kind === 'edit' && (
        <UserForm
          noun={NOUN}
          user={dialog.account}
          groups={groups}
          groupSuggestions={groupNames}
          canHide={isAdmin}
          onClose={() => setDialog(null)}
          onSubmit={async (input, memberOf, primaryGroup) => {
            const { account } = dialog
            // Groups first: they are the likelier to be rejected, and then nothing has changed yet.
            const before = (account.groups_obj ?? []).map((g) => g.name)
            const groupsChanged =
              before.length !== memberOf.length || before.some((g) => !memberOf.includes(g))
            const primaryChanged = primaryGroup !== account.primary_group
            if (groupsChanged || primaryChanged) {
              await api.setServiceAccountGroups(
                account.pk,
                memberOf,
                primaryChanged ? primaryGroup : undefined,
              )
            }
            await api.updateServiceAccount(account.pk, input)
            done(`${input.username} saved.`)
          }}
        />
      )}
      {dialog?.kind === 'tokens' && (
        <TokensDialog
          account={dialog.account}
          onClose={() => setDialog(null)}
          onChanged={setNotice}
        />
      )}
      {dialog?.kind === 'api-keys' && (
        <ApiKeysDialog
          account={dialog.account}
          onClose={() => setDialog(null)}
          onChanged={setNotice}
        />
      )}
      {dialog?.kind === 'certificates' && (
        <Modal
          title={`Certificates of ${dialog.account.username}`}
          onClose={() => setDialog(null)}
          wide
        >
          <DialogContent>
            <CertificateManager
              username={dialog.account.username}
              serviceAccountId={dialog.account.pk}
            />
          </DialogContent>
        </Modal>
      )}
    </>
  )
}
