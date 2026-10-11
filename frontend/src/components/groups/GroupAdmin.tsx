import SearchIcon from '@mui/icons-material/Search'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
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
import { ListPagination } from '../common/ListPagination'
import { Modal } from '../common/Modal'
import { GroupEditor } from './GroupEditor'
import { GroupsTable } from './GroupsTable'
import { JoinGroupForm } from './JoinGroupForm'

const PAGE_SIZE = 20

interface GroupAdminProps {
  /**
   * The operator is an access administrator, who sees every group and edits
   * them. Everyone else sees the visible groups, without their members, and
   * may request to join them.
   */
  admin: boolean
  onClose: () => void
}

/**
 * Lists the authentik groups; access administrators also edit them here, and
 * everyone else may request to join the visible ones.
 */
export function GroupAdmin({ admin, onClose }: GroupAdminProps) {
  const [search, setSearch] = useState('')
  const query = useDebounced(search)
  const [page, setPage] = useState(1)
  // The groups loaded for the request in `key`.
  const [list, setList] = useState<{ key: string; data: Page<PublicGroup | Group> } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [editing, setEditing] = useState<Group | null>(null)
  const [requesting, setRequesting] = useState<PublicGroup | null>(null)
  // The signed-in user's pending join requests; only loaded for non-administrators.
  const [pending, setPending] = useState<JoinRequest[]>([])
  // Bumped after a group was edited or a join request changed, to reload the list.
  const [version, setVersion] = useState(0)
  const requestKey = `${admin}|${query}|${page}|${version}`

  useEffect(() => {
    let cancelled = false
    const load = admin ? api.listGroups : api.listVisibleGroups
    load({ search: query, page, pageSize: PAGE_SIZE })
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
  }, [admin, query, page, requestKey])

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
    if (group.member) return <Chip size="small" label="Member" />
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

  if (editing) {
    return (
      <Modal title={`Group ${editing.name}`} onClose={onClose} wide>
        <GroupEditor
          group={editing}
          onUpdated={setEditing}
          onBack={() => {
            setEditing(null)
            setVersion((v) => v + 1)
          }}
        />
      </Modal>
    )
  }

  if (requesting) {
    return (
      <Modal title={`Join ${requesting.name}`} onClose={onClose}>
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
    )
  }

  return (
    <Modal title="Groups" onClose={onClose} wide>
      <DialogContent sx={{ pt: 0 }}>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          {notice && <Alert severity="success">{notice}</Alert>}
          <Typography variant="body2" color="text.secondary">
            {admin
              ? 'Groups marked visible are listed here for every signed-in user, without their members.'
              : 'Groups the access administrators made visible to everyone. Their members are not shown. You can request to join one; the operators managing it decide.'}
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
        </Stack>
      </DialogContent>
    </Modal>
  )
}
