import OpenInNewIcon from '@mui/icons-material/OpenInNew'
import Alert from '@mui/material/Alert'
import CircularProgress from '@mui/material/CircularProgress'
import DialogContent from '@mui/material/DialogContent'
import IconButton from '@mui/material/IconButton'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { Application, User } from '../../api'
import { errorMessage } from '../../errors'
import { Modal } from '../common/Modal'

interface ApplicationsDialogProps {
  user: User
  onClose: () => void
}

/** Lists the authentik applications a user may access. */
export function ApplicationsDialog({ user, onClose }: ApplicationsDialogProps) {
  // The applications, or null while loading.
  const [applications, setApplications] = useState<Application[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .listUserApplications(user.pk)
      .then((list) => {
        if (!cancelled) setApplications(list)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [user.pk])

  return (
    <Modal title={`Applications of ${user.username}`} onClose={onClose} wide>
      <DialogContent>
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">
            The applications whose policies currently allow {user.username} access.
          </Typography>
          {error && <Alert severity="error">{error}</Alert>}
          {applications === null && !error && (
            <Stack sx={{ alignItems: 'center', py: 2 }}>
              <CircularProgress size={24} />
            </Stack>
          )}
          {applications?.length === 0 && (
            <Typography sx={{ color: 'text.secondary', textAlign: 'center', py: 2 }}>
              {user.username} has no access to any application.
            </Typography>
          )}
          {applications !== null && applications.length > 0 && (
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Group</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell aria-label="Open" />
                </TableRow>
              </TableHead>
              <TableBody>
                {applications.map((app) => (
                  <TableRow key={app.slug} hover>
                    <TableCell>{app.name}</TableCell>
                    <TableCell>{app.group || '—'}</TableCell>
                    <TableCell>{app.description || '—'}</TableCell>
                    <TableCell align="right">
                      {app.launch_url && (
                        <Tooltip title="Open">
                          <IconButton
                            size="small"
                            href={app.launch_url}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <OpenInNewIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Stack>
      </DialogContent>
    </Modal>
  )
}
