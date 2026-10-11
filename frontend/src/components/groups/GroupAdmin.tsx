import SearchIcon from '@mui/icons-material/Search'
import Alert from '@mui/material/Alert'
import DialogContent from '@mui/material/DialogContent'
import InputAdornment from '@mui/material/InputAdornment'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { Group, GroupList } from '../../api'
import { errorMessage } from '../../errors'
import { useDebounced } from '../../hooks/useDebounced'
import { ListPagination } from '../common/ListPagination'
import { Modal } from '../common/Modal'
import { GroupEditor } from './GroupEditor'
import { GroupsTable } from './GroupsTable'

const PAGE_SIZE = 20

/** Lets access administrators list the authentik groups, rename them and edit their members. */
export function GroupAdmin({ onClose }: { onClose: () => void }) {
  const [search, setSearch] = useState('')
  const query = useDebounced(search)
  const [page, setPage] = useState(1)
  // The groups loaded for the request in `key`.
  const [list, setList] = useState<{ key: string; data: GroupList } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState<Group | null>(null)
  // Bumped after a group was edited, to reload the list.
  const [version, setVersion] = useState(0)
  const requestKey = `${query}|${page}|${version}`

  useEffect(() => {
    let cancelled = false
    api
      .listGroups({ search: query, page, pageSize: PAGE_SIZE })
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
  }, [query, page, requestKey])

  if (editing) {
    return (
      <Modal title={`Group ${editing.name}`} onClose={onClose} wide>
        <GroupEditor
          group={editing}
          onRenamed={setEditing}
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
            onEdit={setEditing}
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
