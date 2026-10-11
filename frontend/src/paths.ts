/** Pages next to the user list, each with its own tab in the header. */
export const pagePaths = {
  users: '/',
  groups: '/groups',
  joinRequests: '/join-requests',
  accessRules: '/access-rules',
  audit: '/audit',
} as const

/** Dialogs on the user list that have their own URL, so they can be linked and reloaded. */
export const dialogPaths = {
  create: '/users/new',
} as const

export type RoutedDialog = keyof typeof dialogPaths

/** Returns the dialog the path opens, if any. */
export function dialogForPath(pathname: string): RoutedDialog | null {
  const entry = Object.entries(dialogPaths).find(([, path]) => path === pathname)
  return entry ? (entry[0] as RoutedDialog) : null
}
