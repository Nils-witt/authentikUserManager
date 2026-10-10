import LogoutIcon from '@mui/icons-material/Logout'
import AppBar from '@mui/material/AppBar'
import Button from '@mui/material/Button'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import * as api from '../../api'
import type { Me } from '../../api'

async function signOut() {
  try {
    const { logout_url } = await api.logout()
    // End the authentik session too, so the next login asks for credentials again.
    window.location.assign(logout_url ?? '/auth/login')
  } catch {
    window.location.assign('/auth/login')
  }
}

/** Top bar with the app title, the signed-in operator and a sign-out button. */
export function AppHeader({ me }: { me: Me }) {
  return (
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
  )
}
