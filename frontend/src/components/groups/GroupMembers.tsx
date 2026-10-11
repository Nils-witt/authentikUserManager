import PersonRemoveIcon from '@mui/icons-material/PersonRemove'
import SearchIcon from '@mui/icons-material/Search'
import Alert from '@mui/material/Alert'
import Autocomplete from '@mui/material/Autocomplete'
import Box from '@mui/material/Box'
import IconButton from '@mui/material/IconButton'
import InputAdornment from '@mui/material/InputAdornment'
import LinearProgress from '@mui/material/LinearProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import TextField from '@mui/material/TextField'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { Group, User, UserList } from '../../api'
import { errorMessage } from '../../errors'
import { useConfirm } from '../../hooks/useConfirm'
import { useDebounced } from '../../hooks/useDebounced'
import { ListPagination } from '../common/ListPagination'

const PAGE_SIZE = 10

/** Lists the direct members of a group and adds or removes them. */
export function GroupMembers({ group }: { group: Group }) {
  const [search, setSearch] = useState('')
  const query = useDebounced(search)
  const [page, setPage] = useState(1)
  // The members loaded for the request in `key`.
  const [list, setList] = useState<{ key: string; data: UserList } | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Bumped after every change, to reload the members.
  const [version, setVersion] = useState(0)
  const [confirm, confirmDialog] = useConfirm()
  const requestKey = `${group.pk}|${query}|${page}|${version}`

  useEffect(() => {
    let cancelled = false
    api
      .listGroupMembers(group.pk, { search: query, page, pageSize: PAGE_SIZE })
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
  }, [group.pk, query, page, requestKey])

  async function add(user: User) {
    if (group.is_superuser) {
      const ok = await confirm({
        title: `Add ${user.username} to ${group.name}?`,
        message: 'Members of this group are authentik superusers with full access to authentik.',
        confirmLabel: 'Add',
      })
      if (!ok) return
    }
    try {
      await api.addGroupMember(group.pk, user.pk)
      setVersion((v) => v + 1)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function remove(user: User) {
    const ok = await confirm({
      title: `Remove ${user.username} from ${group.name}?`,
      message: 'The user loses the access this group grants.',
      confirmLabel: 'Remove',
    })
    if (!ok) return
    try {
      await api.removeGroupMember(group.pk, user.pk)
      setVersion((v) => v + 1)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  const members = list?.data.results
  const loading = list?.key !== requestKey && !error
  return (
    <Stack spacing={2}>
      <Typography variant="subtitle1" component="h3">
        Members
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack direction="row" spacing={1.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
        <TextField
          type="search"
          size="small"
          placeholder="Search members…"
          aria-label="Search members"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setPage(1)
          }}
          sx={{ flex: '1 1 220px' }}
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
        <UserPicker onPick={(user) => void add(user)} />
      </Stack>
      <TableContainer component={Paper} variant="outlined" aria-busy={loading}>
        <Box sx={{ height: 4 }}>{loading && <LinearProgress />}</Box>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Username</TableCell>
              <TableCell>Name</TableCell>
              <TableCell aria-label="Actions" />
            </TableRow>
          </TableHead>
          <TableBody>
            {members?.map((user) => (
              <TableRow key={user.pk} hover>
                <TableCell>{user.username}</TableCell>
                <TableCell>{user.name}</TableCell>
                <TableCell align="right">
                  <Tooltip title="Remove from group">
                    <IconButton size="small" color="error" onClick={() => void remove(user)}>
                      <PersonRemoveIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {members?.length === 0 && (
              <TableRow>
                <TableCell colSpan={3} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                  No members found.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      <ListPagination
        pagination={list?.data.pagination}
        page={page}
        onChange={setPage}
        noun="members"
      />
      {confirmDialog}
    </Stack>
  )
}

/** Searches users by name and reports the one picked, then clears itself. */
function UserPicker({ onPick }: { onPick: (user: User) => void }) {
  const [input, setInput] = useState('')
  const query = useDebounced(input)
  // The users found for the search in `query`.
  const [found, setFound] = useState<{ query: string; users: User[] } | null>(null)

  useEffect(() => {
    if (!query) return
    let cancelled = false
    api
      .listUsers({ search: query, page: 1, pageSize: 10 })
      .then((list) => {
        if (!cancelled) setFound({ query, users: list.results })
      })
      .catch(() => {
        // Only suggestions; show none rather than an error.
        if (!cancelled) setFound({ query, users: [] })
      })
    return () => {
      cancelled = true
    }
  }, [query])

  const options = query && found?.query === query ? found.users : []
  return (
    <Autocomplete
      size="small"
      sx={{ flex: '1 1 260px' }}
      options={options}
      value={null}
      inputValue={input}
      onInputChange={(_, value, reason) => {
        // Picking an option sets the input to its label; keep the box empty instead.
        if (reason !== 'reset') setInput(value)
      }}
      onChange={(_, user) => {
        if (!user) return
        setInput('')
        onPick(user)
      }}
      // The server already searched; do not filter its results again.
      filterOptions={(x) => x}
      getOptionLabel={(user) => (user.name ? `${user.username} (${user.name})` : user.username)}
      isOptionEqualToValue={(a, b) => a.pk === b.pk}
      noOptionsText={query ? 'No users found' : 'Type to search users'}
      loading={Boolean(query) && found?.query !== query}
      renderInput={(params) => <TextField {...params} label="Add member" />}
    />
  )
}
