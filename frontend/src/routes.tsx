import { createBrowserRouter, Navigate } from 'react-router'
import App from './App'
import { GroupsPage } from './components/groups/GroupsPage'
import { JoinRequestsPage } from './components/groups/JoinRequestsPage'
import { UserAdmin } from './components/users/UserAdmin'
import { dialogPaths, pagePaths } from './paths'

// The Go server answers unknown paths with index.html (spaHandler), so every
// route here survives a reload.
export const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      {
        // The user list stays mounted while its dialogs open and close.
        element: <UserAdmin />,
        children: [{ index: true }, ...Object.values(dialogPaths).map((path) => ({ path }))],
      },
      { path: pagePaths.groups, element: <GroupsPage /> },
      { path: pagePaths.joinRequests, element: <JoinRequestsPage /> },
      { path: '*', element: <Navigate to={pagePaths.users} replace /> },
    ],
  },
])
