import SearchIcon from '@mui/icons-material/Search'
import Alert from '@mui/material/Alert'
import DialogContent from '@mui/material/DialogContent'
import InputAdornment from '@mui/material/InputAdornment'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { Group, Page, PublicGroup } from '../../api'
import { errorMessage } from '../../errors'
import { useDebounced } from '../../hooks/useDebounced'
import { ListPagination } from '../common/ListPagination'
import { Modal } from '../common/Modal'
import { GroupEditor } from './GroupEditor'
import { GroupsTable } from './GroupsTable'

const PAGE_SIZE = 20

interface GroupAdminProps {
  /**
   * The operator is an access administrator, who sees every group and edits
   * them. Everyone else sees the visible groups, without their members.
   */
  admin: boolean
  onClose: () => void
}

/** Lists the authentik groups; access administrators also edit them here. */
export function GroupAdmin({ admin, onClose }: GroupAdminProps) {
  const [search, setSearch] = useState('')
  const query = useDebounced(search)
  const [page, setPage] = useState(1)
  // The groups loaded for the request in `key`.
  const [list, setList] = useState<{ key: string; data: Page<PublicGroup | Group> } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState<Group | null>(null)
  // Bumped after a group was edited, to reload the list.
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

  return (
    <Modal title="Groups" onClose={onClose} wide>
      <DialogContent sx={{ pt: 0 }}>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <Typography variant="body2" color="text.secondary">
            {admin
              ? 'Groups marked visible are listed here for every signed-in user, without their members.'
              : 'Groups the access administrators made visible to everyone. Their members are not shown.'}
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
