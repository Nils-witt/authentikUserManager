import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Container from '@mui/material/Container'
import LinearProgress from '@mui/material/LinearProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { JoinRequest } from '../../api'
import { errorMessage } from '../../errors'
import { useConfirm } from '../../hooks/useConfirm'

/**
 * Lists the pending requests to join the groups whose members the operator may
 * manage, and approves or rejects them. Approving adds the user to the group.
 */
export function JoinRequests({ onChange }: { onChange: () => void }) {
  // The pending requests, or null while loading.
  const [requests, setRequests] = useState<JoinRequest[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  // The request being decided, so its buttons show progress.
  const [busy, setBusy] = useState<number | null>(null)
  // Bumped after every decision, to reload the requests.
  const [version, setVersion] = useState(0)
  const [confirm, confirmDialog] = useConfirm()

  useEffect(() => {
    let cancelled = false
    api
      .listJoinRequests()
      .then((list) => {
        if (!cancelled) setRequests(list)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [version])

  async function decide(request: JoinRequest, approve: boolean) {
    if (!approve) {
      const ok = await confirm({
        title: `Reject ${request.username}'s request?`,
        message: `${request.username} does not join ${request.group_name}. They may ask again.`,
        confirmLabel: 'Reject',
      })
      if (!ok) return
    }
    setBusy(request.id)
    setError(null)
    setNotice(null)
    try {
      if (approve) {
        await api.approveJoinRequest(request.id)
        setNotice(`${request.username} joined ${request.group_name}.`)
      } else {
        await api.rejectJoinRequest(request.id)
        setNotice(`Request of ${request.username} rejected.`)
      }
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
      // Reload even after a failure: another operator may have decided it meanwhile.
      setVersion((v) => v + 1)
      onChange()
    }
  }

  return (
    <Container component="main" maxWidth="lg" sx={{ py: 3 }}>
      <Stack spacing={2}>
        <Typography variant="h5" component="h2">
          Join requests
        </Typography>
        {error && <Alert severity="error">{error}</Alert>}
        {notice && <Alert severity="success">{notice}</Alert>}
        <Typography variant="body2" color="text.secondary">
          Requests to join the groups whose members you manage. Approving one adds the user to the
          group. Your own requests are decided by someone else.
        </Typography>
        <TableContainer component={Paper} variant="outlined" aria-busy={requests === null}>
          <Box sx={{ height: 4 }}>{requests === null && !error && <LinearProgress />}</Box>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>User</TableCell>
                <TableCell>Group</TableCell>
                <TableCell>Message</TableCell>
                <TableCell>Requested</TableCell>
                <TableCell aria-label="Actions" />
              </TableRow>
            </TableHead>
            <TableBody>
              {requests?.map((request) => (
                <TableRow key={request.id} hover>
                  <TableCell>{request.username}</TableCell>
                  <TableCell>{request.group_name}</TableCell>
                  <TableCell sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                    {request.message || '—'}
                  </TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>
                    {new Date(request.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={1} sx={{ justifyContent: 'flex-end' }}>
                      <Button
                        size="small"
                        color="error"
                        disabled={busy !== null}
                        onClick={() => void decide(request, false)}
                      >
                        Reject
                      </Button>
                      <Button
                        size="small"
                        variant="contained"
                        loading={busy === request.id}
                        disabled={busy !== null && busy !== request.id}
                        onClick={() => void decide(request, true)}
                      >
                        Approve
                      </Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
              {requests?.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                    No pending requests.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Stack>
      {confirmDialog}
    </Container>
  )
}
