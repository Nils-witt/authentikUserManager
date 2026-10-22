import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import LinearProgress from '@mui/material/LinearProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { NotificationPreferences, NotificationSettings as Settings } from '../../api'
import { errorMessage } from '../../errors'

/**
 * Lets the signed-in user choose per category and channel which notifications they receive.
 * Mandatory categories, such as changes to these settings, cannot be turned off.
 */
export function NotificationSettings({ onSaved }: { onSaved: () => void }) {
  const [settings, setSettings] = useState<Settings | null>(null)
  // The preferences being edited; saved ones are in `settings`.
  const [draft, setDraft] = useState<NotificationPreferences | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .notificationSettings()
      .then((value) => {
        if (cancelled) return
        setSettings(value)
        setDraft(value.preferences)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [])

  async function save() {
    if (!draft) return
    setSaving(true)
    try {
      const saved = await api.putNotificationPreferences(draft)
      setSettings(saved)
      setDraft(saved.preferences)
      setError(null)
      onSaved()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const dirty = settings !== null && JSON.stringify(draft) !== JSON.stringify(settings.preferences)

  return (
    <Paper
      variant="outlined"
      component="section"
      aria-labelledby="notification-settings"
      sx={{ p: 2 }}
    >
      <Stack spacing={1.5}>
        <Typography id="notification-settings" variant="h6" component="h2">
          Settings
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Choose which notifications you receive. You are always notified when these settings
          change.
        </Typography>
        {error && <Alert severity="error">{error}</Alert>}
        {!settings || !draft ? (
          !error && <LinearProgress />
        ) : (
          <>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Notification</TableCell>
                  {settings.channels.map((ch) => (
                    <TableCell key={ch.name} align="center">
                      {ch.label}
                    </TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {settings.categories.map((cat) => (
                  <TableRow key={cat.name}>
                    <TableCell>
                      {cat.label}
                      {cat.mandatory && (
                        <Typography variant="caption" color="text.secondary" component="div">
                          Always sent
                        </Typography>
                      )}
                    </TableCell>
                    {settings.channels.map((ch) => (
                      <TableCell key={ch.name} align="center">
                        <Switch
                          checked={cat.mandatory || (draft[cat.name]?.[ch.name] ?? true)}
                          disabled={cat.mandatory || saving}
                          onChange={(e) =>
                            setDraft({
                              ...draft,
                              [cat.name]: { ...draft[cat.name], [ch.name]: e.target.checked },
                            })
                          }
                          slotProps={{ input: { 'aria-label': `${cat.label}: ${ch.label}` } }}
                        />
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <Stack direction="row" spacing={1} sx={{ justifyContent: 'flex-end' }}>
              <Button onClick={() => setDraft(settings.preferences)} disabled={!dirty || saving}>
                Reset
              </Button>
              <Button variant="contained" onClick={() => void save()} disabled={saving}>
                Save
              </Button>
            </Stack>
          </>
        )}
      </Stack>
    </Paper>
  )
}
