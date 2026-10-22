import { useState } from 'react'
import { Outlet } from 'react-router'
import type { Me } from '../../api'
import { useAccess } from '../../hooks/useAccess'
import type { AppContext } from '../../hooks/useAppContext'
import { useJoinRequestCount } from '../../hooks/useJoinRequestCount'
import { useNotificationCount } from '../../hooks/useNotificationCount'
import { AppFooter } from './AppFooter'
import { AppHeader } from './AppHeader'

/** Header with the navigation, the current page and the footer. */
export function AppLayout({ me }: { me: Me }) {
  const [version, setVersion] = useState(0)
  const { access, noAccess, error: accessError } = useAccess(version)
  const canDecideJoins = access !== null && !noAccess
  const joinRequestCount = useJoinRequestCount(canDecideJoins, version)
  // Any change may notify the operator, e.g. about their own account.
  const [notificationVersion, setNotificationVersion] = useState(0)
  const notifications = useNotificationCount(version + notificationVersion)

  const context: AppContext = {
    me,
    access,
    noAccess,
    accessError,
    canDecideJoins,
    version,
    refresh: () => setVersion((v) => v + 1),
    notificationsChanged: () => setNotificationVersion((v) => v + 1),
  }

  return (
    <>
      <AppHeader
        me={me}
        showGroups={access !== null}
        showServiceAccounts={access !== null && !noAccess}
        showJoinRequests={canDecideJoins}
        joinRequestCount={joinRequestCount}
        showCertificates={access?.certificates ?? false}
        showAdmin={access?.admin ?? false}
        showNotifications={notifications.available}
        notificationCount={notifications.count}
      />
      <Outlet context={context} />
      <AppFooter />
    </>
  )
}
