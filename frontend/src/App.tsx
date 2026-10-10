import BlockIcon from '@mui/icons-material/Block'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import DeleteIcon from '@mui/icons-material/Delete'
import EditIcon from '@mui/icons-material/Edit'
import KeyIcon from '@mui/icons-material/Key'
import LogoutIcon from '@mui/icons-material/Logout'
import SearchIcon from '@mui/icons-material/Search'
import Alert from '@mui/material/Alert'
import AppBar from '@mui/material/AppBar'
import Avatar from '@mui/material/Avatar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import CircularProgress from '@mui/material/CircularProgress'
import Container from '@mui/material/Container'
import IconButton from '@mui/material/IconButton'
import InputAdornment from '@mui/material/InputAdornment'
import LinearProgress from '@mui/material/LinearProgress'
import Pagination from '@mui/material/Pagination'
import Paper from '@mui/material/Paper'
import Snackbar from '@mui/material/Snackbar'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import TextField from '@mui/material/TextField'
import Toolbar from '@mui/material/Toolbar'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from './api'
import type { Access, Me, User, UserList } from './api'
import { AccessRules } from './components/AccessRules'
import { useConfirm } from './components/ConfirmDialog'
import { FolderTree } from './components/FolderTree'
import { PasswordForm } from './components/PasswordForm'
import { UserForm } from './components/UserForm'

const PAGE_SIZE = 20

type Dialog =
  | { kind: 'create' }
  | { kind: 'edit'; user: User }
  | { kind: 'password'; user: User }
  | { kind: 'rules' }
  | null

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : '—'
}

/** Ensures the operator is signed in before showing the user admin. */
export default function App() {
  const [me, setMe] = useState<Me | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .me()
      .then(setMe)
      .catch((err: unknown) => {
        // A 401 has already triggered the redirect to the login.
        if (err instanceof api.ApiError && err.status === 401) return
        setError(err instanceof Error ? err.message : String(err))
      })
  }, [])

  if (error) {
    return (
      <Container component="main" sx={{ py: 3 }}>
        <Alert severity="error">{error}</Alert>
      </Container>
    )
  }
  if (!me) {
    return (
      <Stack component="main" spacing={2} sx={{ alignItems: 'center', py: 8 }}>
        <CircularProgress />
        <Typography color="text.secondary">Signing in…</Typography>
      </Stack>
    )
  }
  return <UserAdmin me={me} />
}

async function signOut() {
  try {
    const { logout_url } = await api.logout()
    // End the authentik session too, so the next login asks for credentials again.
    window.location.assign(logout_url ?? '/auth/login')
  } catch {
    window.location.assign('/auth/login')
  }
}

function UserAdmin({ me }: { me: Me }) {
  const [confirm, confirmDialog] = useConfirm()
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  // Selected user folder (path), or null for all users.
  const [folder, setFolder] = useState<string | null>(null)
  const [paths, setPaths] = useState<string[]>([])
  const [access, setAccess] = useState<Access | null>(null)
  const [data, setData] = useState<UserList | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dialog, setDialog] = useState<Dialog>(null)

  // Debounce the search box so we don't query authentik on every keystroke.
  useEffect(() => {
    const id = setTimeout(() => {
      setQuery(search.trim())
      setPage(1)
    }, 300)
    return () => clearTimeout(id)
  }, [search])

  // Bumped after every mutation to refetch the current page.
  const [version, setVersion] = useState(0)
  const requestKey = `${query}|${folder}|${page}|${version}`
  const [loadedKey, setLoadedKey] = useState<string | null>(null)
  const loading = loadedKey !== requestKey

  useEffect(() => {
    let cancelled = false
    api
      .listUsers({ search: query, page, pageSize: PAGE_SIZE, path: folder ?? undefined })
      .then((list) => {
        if (cancelled) return
        setData(list)
        setError(null)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setLoadedKey(requestKey)
      })
    return () => {
      cancelled = true
    }
  }, [query, folder, page, requestKey])

  // Reload the folders after mutations too, since a user's path may have changed.
  useEffect(() => {
    let cancelled = false
    api
      .listUserPaths()
      .then((list) => {
        if (!cancelled) setPaths(list)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      })
    return () => {
      cancelled = true
    }
  }, [version])

  // Reloaded after every change, since an edited rule may change the operator's own scope.
  useEffect(() => {
    api
      .access()
      .then(setAccess)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
  }, [version])
  const noAccess = access !== null && !access.all && access.groups.length === 0

  function selectFolder(path: string | null) {
    setFolder(path)
    setPage(1)
  }

  const done = (message: string) => {
    setDialog(null)
    setNotice(message)
    setVersion((v) => v + 1)
  }

  async function toggleActive(user: User) {
    try {
      await api.updateUser(user.pk, { is_active: !user.is_active })
      done(`${user.username} ${user.is_active ? 'deactivated' : 'activated'}.`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function remove(user: User) {
    const ok = await confirm({
      title: `Delete ${user.username}?`,
      message: 'The user is removed from authentik. This cannot be undone.',
      confirmLabel: 'Delete',
    })
    if (!ok) return
    try {
      await api.deleteUser(user.pk)
      done(`${user.username} deleted.`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const pagination = data?.pagination

  return (
    <>
      <AppBar
        position="static"
        color="default"
        elevation={0}
        sx={{ borderBottom: 1, borderColor: 'divider' }}
      >
        <Toolbar sx={{ gap: 2, flexWrap: 'wrap' }}>
          <Typography variant="h6" component="h1" sx={{ flexGrow: 1 }}>
            Authentik users
          </Typography>
          <Typography variant="body2" color="text.secondary" title={me.email}>
            {me.name || me.username}
          </Typography>
          <Button color="inherit" startIcon={<LogoutIcon />} onClick={() => void signOut()}>
            Sign out
          </Button>
        </Toolbar>
      </AppBar>

      <Container component="main" maxWidth="xl" sx={{ py: 3 }}>
        <Stack
          direction="row"
          spacing={1.5}
          useFlexGap
          sx={{ mb: 2, flexWrap: 'wrap', alignItems: 'center' }}
        >
          <TextField
            type="search"
            size="small"
            placeholder="Search users…"
            aria-label="Search users"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            sx={{ flex: '1 1 280px', maxWidth: 400 }}
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
          <Box sx={{ flexGrow: 1 }} />
          {access?.admin && (
            <Button variant="outlined" onClick={() => setDialog({ kind: 'rules' })}>
              Access rules
            </Button>
          )}
          {access && !noAccess && (
            <Button variant="contained" onClick={() => setDialog({ kind: 'create' })}>
              New user
            </Button>
          )}
        </Stack>

        <Stack spacing={1.5} sx={{ mb: 2, '&:empty': { display: 'none' } }}>
          {error && <Alert severity="error">{error}</Alert>}
          {noAccess && (
            <Alert severity="warning">
              Your groups do not grant access to any users. Ask an administrator to add an access
              rule.
            </Alert>
          )}
          {access && !access.all && !noAccess && (
            <Alert severity="info">You can manage members of: {access.groups.join(', ')}</Alert>
          )}
        </Stack>

        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: { xs: 'minmax(0, 1fr)', md: '240px minmax(0, 1fr)' },
            gap: 2,
            alignItems: 'start',
          }}
        >
          <FolderTree paths={paths} selected={folder} onSelect={selectFolder} />
          <Box component="section">
            <TableContainer component={Paper} variant="outlined" aria-busy={loading}>
              <Box sx={{ height: 4 }}>{loading && <LinearProgress />}</Box>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Username</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Email</TableCell>
                    <TableCell>Groups</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Last login</TableCell>
                    <TableCell aria-label="Actions" />
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data?.results.map((user) => (
                    <TableRow
                      key={user.pk}
                      hover
                      sx={user.is_active ? undefined : { '& td': { color: 'text.disabled' } }}
                    >
                      <TableCell>
                        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                          <Avatar
                            src={user.avatar || undefined}
                            alt=""
                            sx={{ width: 24, height: 24 }}
                          />
                          <span>{user.username}</span>
                          {user.is_superuser && (
                            <Chip size="small" variant="outlined" label="admin" />
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell>{user.name}</TableCell>
                      <TableCell>{user.email || '—'}</TableCell>
                      <TableCell
                        sx={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis' }}
                      >
                        {(user.groups_obj ?? []).map((g) => g.name).join(', ') || '—'}
                      </TableCell>
                      <TableCell>{user.type.replaceAll('_', ' ')}</TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          color={user.is_active ? 'success' : 'default'}
                          variant="outlined"
                          label={user.is_active ? 'active' : 'inactive'}
                        />
                      </TableCell>
                      <TableCell>{formatDate(user.last_login)}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="Edit">
                          <IconButton
                            size="small"
                            onClick={() => setDialog({ kind: 'edit', user })}
                          >
                            <EditIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Set password">
                          <IconButton
                            size="small"
                            onClick={() => setDialog({ kind: 'password', user })}
                          >
                            <KeyIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title={user.is_active ? 'Deactivate' : 'Activate'}>
                          <IconButton size="small" onClick={() => void toggleActive(user)}>
                            {user.is_active ? (
                              <BlockIcon fontSize="small" />
                            ) : (
                              <CheckCircleIcon fontSize="small" />
                            )}
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton size="small" color="error" onClick={() => void remove(user)}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                  {data && data.results.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={8} align="center" sx={{ color: 'text.secondary', py: 4 }}>
                        No users found.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>

            {pagination && pagination.total_pages > 1 && (
              <Stack spacing={1} sx={{ alignItems: 'center', mt: 2 }}>
                <Pagination
                  color="primary"
                  count={pagination.total_pages}
                  page={page}
                  onChange={(_, p) => setPage(p)}
                />
                <Typography variant="body2" color="text.secondary">
                  {pagination.count} users
                </Typography>
              </Stack>
            )}
          </Box>
        </Box>
      </Container>

      <Snackbar
        open={notice !== null}
        autoHideDuration={6000}
        onClose={(_, reason) => {
          if (reason !== 'clickaway') setNotice(null)
        }}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="success" variant="filled" onClose={() => setNotice(null)}>
          {notice}
        </Alert>
      </Snackbar>
      {confirmDialog}

      {dialog?.kind === 'create' && (
        <UserForm
          defaultPath={folder ?? undefined}
          groups={access && !access.all ? access.groups : undefined}
          onClose={() => setDialog(null)}
          onSubmit={async (input) => {
            const user = await api.createUser(input)
            done(`${user.username} created. Set a password so they can log in.`)
          }}
        />
      )}
      {dialog?.kind === 'edit' && (
        <UserForm
          user={dialog.user}
          onClose={() => setDialog(null)}
          onSubmit={async (input) => {
            await api.updateUser(dialog.user.pk, input)
            done(`${input.username} saved.`)
          }}
        />
      )}
      {dialog?.kind === 'rules' && (
        <AccessRules
          onClose={() => {
            setDialog(null)
            setVersion((v) => v + 1)
          }}
        />
      )}
      {dialog?.kind === 'password' && (
        <PasswordForm
          user={dialog.user}
          onClose={() => setDialog(null)}
          onSubmit={async (password) => {
            await api.setPassword(dialog.user.pk, password)
            done(`Password for ${dialog.user.username} updated.`)
          }}
        />
      )}
    </>
  )
}
