import SearchIcon from '@mui/icons-material/Search'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import Container from '@mui/material/Container'
import InputAdornment from '@mui/material/InputAdornment'
import MenuItem from '@mui/material/MenuItem'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { AuditAction, AuditEntry } from '../../api'
import { errorMessage } from '../../errors'

const ACTION_LABELS: Record<AuditAction, string> = {
  'user.created': 'User created',
  'user.updated': 'User updated',
  'user.deleted': 'User deleted',
  'user.group_added': 'Added to group',
  'user.group_removed': 'Removed from group',
  'user.primary_group_changed': 'Primary group changed',
  'user.recovery_email_sent': 'Recovery email sent',
  'user.certificate_issued': 'Certificate issued',
  'user.certificate_key_downloaded': 'Certificate key downloaded',
  'user.certificate_revoked': 'Certificate revoked',
  'user.certificate_imported': 'Certificate imported',
  'user.certificate_assigned': 'Certificate assigned',
  'user.access_denied': 'Access denied',
  'service_account.created': 'Service account created',
  'service_account.updated': 'Service account updated',
  'service_account.deleted': 'Service account deleted',
  'service_account.token_created': 'Token created',
  'service_account.token_deleted': 'Token deleted',
  'service_account.api_key_created': 'API key created',
  'service_account.api_key_deleted': 'API key deleted',
  'certificate_authority.created': 'Certificate authority added',
  'certificate_authority.updated': 'Certificate authority changed',
  'certificate_authority.default_changed': 'Default certificate authority changed',
  'access_rule.saved': 'Access rule saved',
  'access_rule.deleted': 'Access rule deleted',
  'group.created': 'Group created',
  'group.renamed': 'Group renamed',
  'group.visibility_changed': 'Group visibility changed',
  'group.path_changed': 'Group moved',
  'group.join_requested': 'Join requested',
  'group.join_withdrawn': 'Join request withdrawn',
  'group.join_approved': 'Join request approved',
  'group.join_rejected': 'Join request rejected',
  'auth.login': 'Signed in',
  'auth.login_failed': 'Sign-in failed',
  'auth.logout': 'Signed out',
  'auth.session_ended': 'Session ended (account gone)',
  'service_api.api_key_rejected': 'API key refused',
}

const ACTIONS = Object.keys(ACTION_LABELS) as AuditAction[]

/** Lets access administrators review the changes operators made, newest first. */
export function AuditLog() {
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [action, setAction] = useState<AuditAction | ''>('')
  // The entries loaded for the filters in `key`.
  const [log, setLog] = useState<{ key: string; entries: AuditEntry[]; next?: number } | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const filterKey = `${query}|${action}`
  const current = log?.key === filterKey ? log : null

  // Debounce the search box so we don't query on every keystroke.
  useEffect(() => {
    const id = setTimeout(() => setQuery(search.trim()), 300)
    return () => clearTimeout(id)
  }, [search])

  useEffect(() => {
    let cancelled = false
    api
      .listAudit({ search: query, action: action || undefined })
      .then((page) => {
        if (cancelled) return
        setLog({ key: filterKey, entries: page.entries, next: page.next })
        setError(null)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setLog({ key: filterKey, entries: [] })
        setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [query, action, filterKey])

  async function loadMore() {
    if (!current) return
    setLoadingMore(true)
    try {
      const page = await api.listAudit({
        search: query,
        action: action || undefined,
        before: current.next,
      })
      // Ignore the page when the filters changed meanwhile.
      setLog((prev) =>
        prev?.key === current.key
          ? { key: prev.key, entries: [...prev.entries, ...page.entries], next: page.next }
          : prev,
      )
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoadingMore(false)
    }
  }

  return (
    <Container component="main" maxWidth="xl" sx={{ py: 3 }}>
      <Stack spacing={2}>
        <Typography variant="h5" component="h2">
          Audit log
        </Typography>
        {error && <Alert severity="error">{error}</Alert>}
        <Stack direction="row" spacing={1.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
          <TextField
            type="search"
            size="small"
            placeholder="Operator or target…"
            aria-label="Search by operator or target"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            sx={{ flex: '1 1 220px', maxWidth: 400 }}
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
          <TextField
            select
            size="small"
            label="Action"
            value={action}
            onChange={(e) => setAction(e.target.value as AuditAction | '')}
            sx={{ minWidth: 200 }}
          >
            <MenuItem value="">All actions</MenuItem>
            {ACTIONS.map((a) => (
              <MenuItem key={a} value={a}>
                {ACTION_LABELS[a]}
              </MenuItem>
            ))}
          </TextField>
        </Stack>
        <AuditTable entries={current?.entries ?? null} />
        {current?.next !== undefined && (
          <Stack direction="row" sx={{ justifyContent: 'center' }}>
            <Button onClick={() => void loadMore()} disabled={loadingMore}>
              Load more
            </Button>
          </Stack>
        )}
      </Stack>
    </Container>
  )
}

function AuditTable({ entries }: { entries: AuditEntry[] | null }) {
  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Time</TableCell>
            <TableCell>Operator</TableCell>
            <TableCell>Action</TableCell>
            <TableCell>Target</TableCell>
            <TableCell>Details</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {entries?.map((e) => (
            <TableRow key={e.id}>
              <TableCell sx={{ whiteSpace: 'nowrap' }}>
                {new Date(e.time).toLocaleString()}
              </TableCell>
              <TableCell>{e.actor || '—'}</TableCell>
              <TableCell sx={{ whiteSpace: 'nowrap' }}>
                {ACTION_LABELS[e.action] ?? e.action}
              </TableCell>
              <TableCell>{e.target || '—'}</TableCell>
              <TableCell sx={{ whiteSpace: 'normal' }}>
                <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
                  {Object.entries(e.details).map(([key, value]) => (
                    <Chip key={key} size="small" variant="outlined" label={`${key}: ${value}`} />
                  ))}
                </Stack>
              </TableCell>
            </TableRow>
          ))}
          {entries === null && (
            <TableRow>
              <TableCell colSpan={5} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                Loading…
              </TableCell>
            </TableRow>
          )}
          {entries?.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                No entries.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
