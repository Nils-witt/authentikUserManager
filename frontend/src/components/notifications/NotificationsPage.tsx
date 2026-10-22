import DeleteIcon from '@mui/icons-material/Delete'
import DoneIcon from '@mui/icons-material/Done'
import DoneAllIcon from '@mui/icons-material/DoneAll'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import Container from '@mui/material/Container'
import IconButton from '@mui/material/IconButton'
import LinearProgress from '@mui/material/LinearProgress'
import List from '@mui/material/List'
import ListItem from '@mui/material/ListItem'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { Notification, NotificationCategory } from '../../api'
import { errorMessage } from '../../errors'
import { useAppContext } from '../../hooks/useAppContext'
import { useConfirm } from '../../hooks/useConfirm'
import { NoticeSnackbar } from '../common/NoticeSnackbar'
import { NotificationSettings } from './NotificationSettings'

const CATEGORY_LABELS: Record<NotificationCategory, string> = {
  profile: 'Profile',
  certificate: 'Certificate',
  join_request: 'Join request',
  settings: 'Settings',
}

/** Returns n marked read now, unless it was read before. */
function readNow(n: Notification): Notification {
  return { ...n, read_at: n.read_at ?? new Date().toISOString() }
}

/** The signed-in user's notifications, newest first, and the settings choosing which ones they receive. */
export function NotificationsPage() {
  const { notificationsChanged } = useAppContext()
  const [list, setList] = useState<{ notifications: Notification[]; next?: number } | null>(null)
  // Bumped to load the list again from the start.
  const [reload, setReload] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [confirm, confirmDialog] = useConfirm()

  useEffect(() => {
    let cancelled = false
    api
      .listNotifications()
      .then((page) => {
        if (cancelled) return
        setList({ notifications: page.notifications, next: page.next })
        setError(null)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setList({ notifications: [] })
        setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [reload])

  async function loadMore() {
    if (list?.next === undefined) return
    setLoadingMore(true)
    try {
      const page = await api.listNotifications({ before: list.next })
      setList((prev) => ({
        notifications: [...(prev?.notifications ?? []), ...page.notifications],
        next: page.next,
      }))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoadingMore(false)
    }
  }

  /** Runs a change, then updates the list with `update` and the unread count. */
  async function change(
    action: () => Promise<void>,
    update: (n: Notification[]) => Notification[],
  ) {
    try {
      await action()
      setList((prev) => prev && { ...prev, notifications: update(prev.notifications) })
      setError(null)
      notificationsChanged()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  const markRead = (id: number) =>
    change(
      () => api.markNotificationRead(id),
      (ns) => ns.map((n) => (n.id === id ? readNow(n) : n)),
    )

  const remove = (id: number) =>
    change(
      () => api.deleteNotification(id),
      (ns) => ns.filter((n) => n.id !== id),
    )

  const markAllRead = () => change(api.markAllNotificationsRead, (ns) => ns.map(readNow))

  async function removeAll() {
    const ok = await confirm({
      title: 'Delete all notifications?',
      message: 'Every notification is deleted, read or not. This cannot be undone.',
      confirmLabel: 'Delete all',
    })
    if (ok) await change(api.deleteAllNotifications, () => [])
  }

  const notifications = list?.notifications ?? []
  const hasUnread = notifications.some((n) => n.read_at === null)

  return (
    <Container component="main" maxWidth="md" sx={{ py: 3 }}>
      <Stack spacing={2}>
        <Stack
          direction="row"
          spacing={1}
          useFlexGap
          sx={{ alignItems: 'center', flexWrap: 'wrap' }}
        >
          <Typography variant="h5" component="h2" sx={{ flexGrow: 1 }}>
            Notifications
          </Typography>
          <Button
            startIcon={<DoneAllIcon />}
            onClick={() => void markAllRead()}
            disabled={!hasUnread}
          >
            Mark all read
          </Button>
          <Button
            color="error"
            startIcon={<DeleteIcon />}
            onClick={() => void removeAll()}
            disabled={notifications.length === 0}
          >
            Delete all
          </Button>
        </Stack>
        {error && <Alert severity="error">{error}</Alert>}
        {list === null ? (
          <LinearProgress />
        ) : notifications.length === 0 ? (
          <Typography color="text.secondary">No notifications.</Typography>
        ) : (
          <Paper variant="outlined">
            <List disablePadding>
              {notifications.map((n, i) => (
                <NotificationItem
                  key={n.id}
                  notification={n}
                  divider={i < notifications.length - 1}
                  onRead={() => void markRead(n.id)}
                  onDelete={() => void remove(n.id)}
                />
              ))}
            </List>
          </Paper>
        )}
        {list?.next !== undefined && (
          <Stack direction="row" sx={{ justifyContent: 'center' }}>
            <Button onClick={() => void loadMore()} disabled={loadingMore}>
              Load more
            </Button>
          </Stack>
        )}
        <NotificationSettings
          onSaved={() => {
            setNotice('Notification settings saved')
            // Saving always sends a notification about the change.
            setReload((r) => r + 1)
            notificationsChanged()
          }}
        />
      </Stack>
      {confirmDialog}
      <NoticeSnackbar notice={notice} onClose={() => setNotice(null)} />
    </Container>
  )
}

interface NotificationItemProps {
  notification: Notification
  divider: boolean
  onRead: () => void
  onDelete: () => void
}

function NotificationItem({ notification: n, divider, onRead, onDelete }: NotificationItemProps) {
  const unread = n.read_at === null
  return (
    <ListItem
      divider={divider}
      alignItems="flex-start"
      sx={{ bgcolor: unread ? 'action.hover' : undefined }}
      secondaryAction={
        <Stack direction="row">
          {unread && (
            <IconButton aria-label={`Mark "${n.header}" read`} title="Mark read" onClick={onRead}>
              <DoneIcon />
            </IconButton>
          )}
          <IconButton aria-label={`Delete "${n.header}"`} title="Delete" onClick={onDelete}>
            <DeleteIcon />
          </IconButton>
        </Stack>
      }
    >
      <Box sx={{ pr: 10, minWidth: 0 }}>
        <Stack
          direction="row"
          spacing={1}
          useFlexGap
          sx={{ alignItems: 'center', flexWrap: 'wrap' }}
        >
          <Typography component="h3" variant="subtitle1" sx={{ fontWeight: unread ? 700 : 500 }}>
            {n.header}
          </Typography>
          <Chip size="small" variant="outlined" label={CATEGORY_LABELS[n.category] ?? n.category} />
          <Typography variant="caption" color="text.secondary">
            {new Date(n.created_at).toLocaleString()}
          </Typography>
        </Stack>
        {/* Messages list changes on separate lines. */}
        <Typography
          variant="body2"
          sx={{ whiteSpace: 'pre-line', overflowWrap: 'anywhere', mt: 0.5 }}
        >
          {n.message}
        </Typography>
      </Box>
    </ListItem>
  )
}
