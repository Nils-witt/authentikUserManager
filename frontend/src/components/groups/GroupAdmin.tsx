import AddIcon from '@mui/icons-material/Add'
import SearchIcon from '@mui/icons-material/Search'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import Container from '@mui/material/Container'
import DialogContent from '@mui/material/DialogContent'
import InputAdornment from '@mui/material/InputAdornment'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { Group, JoinRequest, Page, PublicGroup } from '../../api'
import { errorMessage } from '../../errors'
import { useDebounced } from '../../hooks/useDebounced'
import { useGroupPaths } from '../../hooks/useGroupPaths'
import { ListPagination } from '../common/ListPagination'
import { Modal } from '../common/Modal'
import { FolderTree } from '../folders/FolderTree'
import { CreateGroupForm } from './CreateGroupForm'
import { GroupEditor } from './GroupEditor'
import { GroupMembers } from './GroupMembers'
import { GroupsTable } from './GroupsTable'
import { JoinGroupForm } from './JoinGroupForm'

const PAGE_SIZE = 20

interface GroupAdminProps {
  /**
   * The operator is an access administrator, who sees every group and edits
   * them. Everyone else sees the visible groups, may request to join them and
   * sees the members of the groups they manage.
   */
  admin: boolean
  /** Called after a group was edited; its members may include the operator. */
  onChange: () => void
}

/**
 * Lists the authentik groups; access administrators also edit them here, and
 * everyone else may request to join the visible ones.
 */
export function GroupAdmin({ admin, onChange }: GroupAdminProps) {
  const [search, setSearch] = useState('')
  const query = useDebounced(search)
  const [page, setPage] = useState(1)
  // Selected group folder (path), or null for all groups.
  const [folder, setFolder] = useState<string | null>(null)
  // The groups loaded for the request in `key`.
  const [list, setList] = useState<{ key: string; data: Page<PublicGroup | Group> } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [editing, setEditing] = useState<Group | null>(null)
  const [creating, setCreating] = useState(false)
  const [requesting, setRequesting] = useState<PublicGroup | null>(null)
  // The group whose members a non-administrator managing it views.
  const [viewing, setViewing] = useState<PublicGroup | null>(null)
  // The signed-in user's pending join requests; only loaded for non-administrators.
  const [pending, setPending] = useState<JoinRequest[]>([])
  // Bumped after a group was edited or a join request changed, to reload the list.
  const [version, setVersion] = useState(0)
  const requestKey = `${admin}|${query}|${folder}|${page}|${version}`
  const { paths, error: pathsError } = useGroupPaths(version)

  useEffect(() => {
    let cancelled = false
    const load = admin ? api.listGroups : api.listVisibleGroups
    load({ search: query, path: folder, page, pageSize: PAGE_SIZE })
      .then((data) => {
        if (cancelled) return
        setList({ key: requestKey, data })
        setError(null)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [admin, query, folder, page, requestKey])

  useEffect(() => {
    if (admin) return
    let cancelled = false
    api
      .listMyJoinRequests()
      .then((requests) => {
        if (!cancelled) setPending(requests.filter((r) => r.status === 'pending'))
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [admin, version])

  async function withdraw(request: JoinRequest) {
    setNotice(null)
    try {
      await api.withdrawJoinRequest(request.id)
      setNotice(`Request to join ${request.group_name} withdrawn.`)
      setVersion((v) => v + 1)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  function renderJoin(group: PublicGroup) {
    const membership = renderMembership(group)
    if (!group.manageable) return membership
    return (
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', justifyContent: 'flex-end' }}>
        {membership}
        <Button size="small" onClick={() => setViewing(group)}>
          Members
        </Button>
      </Stack>
    )
  }

  function renderMembership(group: PublicGroup) {
    if (group.member) return <Chip size="small" label="Member" />
    if (!group.joinable) return null
    const request = pending.find((r) => r.group_pk === group.pk)
    if (request) {
      return (
        <Stack
          direction="row"
          spacing={1}
          sx={{ alignItems: 'center', justifyContent: 'flex-end' }}
        >
          <Chip size="small" variant="outlined" color="info" label="Requested" />
          <Button size="small" onClick={() => void withdraw(request)}>
            Withdraw
          </Button>
        </Stack>
      )
    }
    return (
      <Button
        size="small"
        variant="outlined"
        onClick={() => {
          setNotice(null)
          setRequesting(group)
        }}
      >
        Request to join
      </Button>
    )
  }

  function closeEditor() {
    setEditing(null)
    setVersion((v) => v + 1)
    onChange()
  }

  return (
    <Container component="main" maxWidth="lg" sx={{ py: 3 }}>
      <Stack spacing={2}>
        <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography variant="h5" component="h2">
            Groups
          </Typography>
          {admin && (
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => {
                setNotice(null)
                setCreating(true)
              }}
            >
              New group
            </Button>
          )}
        </Stack>
        {(error ?? pathsError) && <Alert severity="error">{error ?? pathsError}</Alert>}
        {notice && <Alert severity="success">{notice}</Alert>}
        <Typography variant="body2" color="text.secondary">
          {admin
            ? 'Groups marked visible are listed here for every signed-in user, without their members.'
            : 'Your groups, the groups of the users you manage, and the groups the access administrators made visible to everyone. You see the members of the groups you manage only. You can request to join a visible group; the operators managing it decide.'}
        </Typography>
        <TextField
          type="search"
          size="small"
          placeholder="Search groups…"
          aria-label="Search groups"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setPage(1)
          }}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon fontSize="small" />
                </InputAdornment>
              ),
            },
          }}
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
            selected={folder}
            onSelect={(path) => {
              setFolder(path)
              setPage(1)
            }}
            noun="groups"
          />
          <Box component="section">
            <GroupsTable
              groups={list?.data.results}
              loading={list?.key !== requestKey && !error}
              onEdit={admin ? setEditing : undefined}
              renderJoin={admin ? undefined : renderJoin}
            />
            <ListPagination
              pagination={list?.data.pagination}
              page={page}
              onChange={setPage}
              noun="groups"
            />
          </Box>
        </Box>
      </Stack>

      {creating && (
        <Modal title="New group" onClose={() => setCreating(false)}>
          <CreateGroupForm
            initialPath={folder ?? ''}
            onCreated={(group) => {
              setNotice(`Created ${group.name}.`)
              setCreating(false)
              setVersion((v) => v + 1)
              // Continue with the new group, to add its members.
              setEditing(group)
            }}
            onBack={() => setCreating(false)}
          />
        </Modal>
      )}

      {editing && (
        <Modal title={`Group ${editing.name}`} onClose={closeEditor} wide>
          <GroupEditor group={editing} onUpdated={setEditing} onBack={closeEditor} />
        </Modal>
      )}

      {viewing && (
        <Modal title={`Group ${viewing.name}`} onClose={() => setViewing(null)} wide>
          <DialogContent sx={{ pt: 0 }}>
            <GroupMembers group={viewing} readOnly />
          </DialogContent>
        </Modal>
      )}

      {requesting && (
        <Modal title={`Join ${requesting.name}`} onClose={() => setRequesting(null)}>
          <JoinGroupForm
            group={requesting}
            onRequested={() => {
              setNotice(`Requested to join ${requesting.name}.`)
              setRequesting(null)
              setVersion((v) => v + 1)
            }}
            onBack={() => setRequesting(null)}
          />
        </Modal>
      )}
    </Container>
  )
}
