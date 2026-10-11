import Alert from '@mui/material/Alert'
import Stack from '@mui/material/Stack'
import type { Access } from '../../api'

interface StatusAlertsProps {
  /** Error messages to show; null entries are skipped. */
  errors: (string | null)[]
  access: Access | null
  /** The operator's groups grant access to nobody. */
  noAccess: boolean
}

/** Errors and the operator's access scope, shown above the user table. */
export function StatusAlerts({ errors, access, noAccess }: StatusAlertsProps) {
  // Several requests can fail for the same reason; show each message once.
  const messages = [...new Set(errors.filter((e) => e !== null))]
  return (
    <Stack spacing={1.5} sx={{ mb: 2, '&:empty': { display: 'none' } }}>
      {messages.map((message) => (
        <Alert key={message} severity="error">
          {message}
        </Alert>
      ))}
      {noAccess && (
        <Alert severity="warning">
          Your groups do not grant access to any other users. Ask an administrator to add an access
          rule.
        </Alert>
      )}
      {access && !access.all && !noAccess && (
        <Alert severity="info">You can manage members of: {access.groups.join(', ')}</Alert>
      )}
    </Stack>
  )
}
