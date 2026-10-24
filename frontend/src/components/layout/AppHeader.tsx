import LogoutIcon from '@mui/icons-material/Logout'
import NotificationsIcon from '@mui/icons-material/Notifications'
import AppBar from '@mui/material/AppBar'
import Badge from '@mui/material/Badge'
import Button from '@mui/material/Button'
import IconButton from '@mui/material/IconButton'
import Tab from '@mui/material/Tab'
import Tabs from '@mui/material/Tabs'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { Link, useLocation } from 'react-router'
import * as api from '../../api'
import type { Me } from '../../api'
import { pagePaths } from '../../paths'

async function signOut() {
  try {
    const { logout_url } = await api.logout()
    // End the authentik session too, so the next login asks for credentials again.
    window.location.assign(logout_url ?? '/auth/login')
  } catch {
    window.location.assign('/auth/login')
  }
}

interface AppHeaderProps {
  me: Me
  /** Show the groups tab. */
  showGroups: boolean
  /** Show the service accounts tab. */
  showServiceAccounts: boolean
  /** Show the join requests tab. */
  showJoinRequests: boolean
  /** Number of pending join requests, shown on the join requests tab. */
  joinRequestCount: number
  /** Show the tab of the signed-in user's own certificates, and the issued certificates tab to administrators. */
  showCertificates: boolean
  /** Show the access rules, audit log, issued certificates and certificate authorities tabs. */
  showAdmin: boolean
  /** Show the notifications button; the user receives notifications. */
  showNotifications: boolean
  /** Number of unread notifications, shown on the notifications button. */
  notificationCount: number
}

/** Top bar with the app title, the page tabs, the signed-in operator and a sign-out button. */
export function AppHeader({
  me,
  showGroups,
  showServiceAccounts,
  showJoinRequests,
  joinRequestCount,
  showCertificates,
  showAdmin,
  showNotifications,
  notificationCount,
}: AppHeaderProps) {
  const { pathname, search } = useLocation()
  const onOtherPage = Object.values(pagePaths).some(
    (path) => path !== pagePaths.users && path === pathname,
  )
  // The users tab returns to the list's last filters, which live in its query.
  const [usersSearch, setUsersSearch] = useState(search)
  if (!onOtherPage && search !== usersSearch) setUsersSearch(search)

  const tabs = [
    { path: pagePaths.users, label: 'Users', search: usersSearch },
    showServiceAccounts && { path: pagePaths.serviceAccounts, label: 'Service accounts' },
    showGroups && { path: pagePaths.groups, label: 'Groups' },
    showJoinRequests && {
      path: pagePaths.joinRequests,
      label: (
        <Badge badgeContent={joinRequestCount} color="primary" max={99} sx={{ pr: 1.5 }}>
          Join requests
        </Badge>
      ),
      ariaLabel: joinRequestCount > 0 ? `Join requests (${joinRequestCount} pending)` : undefined,
    },
    showCertificates && { path: pagePaths.certificates, label: 'My certificates' },
    showAdmin && { path: pagePaths.accessRules, label: 'Access rules' },
    showAdmin && { path: pagePaths.audit, label: 'Audit log' },
    showAdmin &&
      showCertificates && {
        path: pagePaths.issuedCertificates,
        label: 'Issued certificates',
      },
    showAdmin &&
      showCertificates && {
        path: pagePaths.certificateAuthorities,
        label: 'Certificate authorities',
      },
  ].filter((tab) => tab !== false)
  // The user list's dialogs have their own paths; they belong to the users tab. The
  // notifications page has no tab.
  const current =
    pathname === pagePaths.notifications
      ? false
      : (tabs.find((tab) => tab.path === pathname)?.path ?? pagePaths.users)

  return (
    <AppBar
      position="static"
      color="default"
      elevation={0}
      sx={{ borderBottom: 1, borderColor: 'divider' }}
    >
      <Toolbar sx={{ gap: 2, flexWrap: 'wrap' }}>
        <Typography variant="h6" component="h1">
          Authentik manager
        </Typography>
        <Tabs value={current} component="nav" aria-label="Pages" sx={{ flexGrow: 1 }}>
          {tabs.map((tab) => (
            <Tab
              key={tab.path}
              value={tab.path}
              label={tab.label}
              aria-label={'ariaLabel' in tab ? tab.ariaLabel : undefined}
              component={Link}
              to={{ pathname: tab.path, search: 'search' in tab ? tab.search : '' }}
            />
          ))}
        </Tabs>
        {showNotifications && (
          <IconButton
            component={Link}
            to={pagePaths.notifications}
            color={pathname === pagePaths.notifications ? 'primary' : 'default'}
            aria-label={
              notificationCount > 0
                ? `Notifications (${notificationCount} unread)`
                : 'Notifications'
            }
            title="Notifications"
          >
            <Badge badgeContent={notificationCount} color="primary" max={99}>
              <NotificationsIcon />
            </Badge>
          </IconButton>
        )}
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
