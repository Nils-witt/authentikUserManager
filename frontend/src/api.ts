export type UserType =
  | 'internal'
  | 'external'
  | 'service_account'
  | 'internal_service_account'

export const USER_TYPES: UserType[] = [
  'internal',
  'external',
  'service_account',
  'internal_service_account',
]

export interface User {
  pk: number
  uuid: string
  username: string
  name: string
  email: string
  is_active: boolean
  is_superuser: boolean
  type: UserType
  path: string
  avatar: string
  last_login: string | null
  date_joined: string
  /** Groups the user is a direct member of. */
  groups_obj?: { pk: string; name: string }[] | null
}

export interface Pagination {
  count: number
  current: number
  total_pages: number
}

export interface UserList {
  pagination: Pagination
  results: User[]
}

export interface UserInput {
  username: string
  name: string
  email: string
  is_active: boolean
  path: string
  type: UserType
}

export interface CreateUserInput extends UserInput {
  /** Group the new user joins; required for operators with restricted access. */
  group?: string
}

/** The users the signed-in operator may manage. */
export interface Access {
  /** Every user, including superusers. */
  all: boolean
  /** Target groups whose members may be managed, when `all` is false. */
  groups: string[]
  /** The operator may edit the access rules. */
  admin: boolean
}

/** Members of operator_group may manage members of target_groups ('*': all users). */
export interface AccessRule {
  operator_group: string
  target_groups: string[]
}

export const WILDCARD = '*'

/** Error returned by the backend; `fields` holds per-field validation messages. */
export class ApiError extends Error {
  readonly status: number
  readonly fields: Record<string, string[]>

  constructor(status: number, message: string, fields: Record<string, string[]> = {}) {
    super(message)
    this.status = status
    this.fields = fields
  }
}

/** Signed-in operator, as returned by /auth/me. */
export interface Me {
  sub: string
  username: string
  name: string
  email: string
  groups: string[]
}

/** Starts the OIDC login; the backend redirects to authentik and back. */
export function redirectToLogin(): never {
  window.location.assign('/auth/login')
  throw new ApiError(401, 'Redirecting to login…')
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 401) {
    // Session missing or expired.
    redirectToLogin()
  }
  if (!res.ok) {
    let message = `Request failed (${res.status})`
    let fields: Record<string, string[]> = {}
    try {
      const data = (await res.json()) as { error?: string; fields?: Record<string, string[]> }
      message = data.error ?? message
      fields = data.fields ?? {}
    } catch {
      // Non-JSON error body; keep the generic message.
    }
    throw new ApiError(res.status, message, fields)
  }
  if (res.status === 204) {
    return undefined as T
  }
  return (await res.json()) as T
}

export function listUsers(params: {
  search: string
  page: number
  pageSize: number
  /** Only users in this folder or one of its subfolders. */
  path?: string
}) {
  const q = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
  })
  if (params.search) q.set('search', params.search)
  if (params.path) q.set('path_startswith', params.path)
  return request<UserList>('GET', `/api/users?${q}`)
}

/** Every distinct user path (folder), e.g. "users" or "users/staff". */
export const listUserPaths = () =>
  request<{ paths: string[] }>('GET', '/api/users/paths').then((res) => res.paths)

export const access = () => request<Access>('GET', '/api/access')

export const listRules = () =>
  request<{ rules: AccessRule[] }>('GET', '/api/access/rules').then((res) => res.rules)

export const putRule = (rule: AccessRule) =>
  request<AccessRule>('PUT', `/api/access/rules/${encodeURIComponent(rule.operator_group)}`, {
    target_groups: rule.target_groups,
  })

export const deleteRule = (operatorGroup: string) =>
  request<void>('DELETE', `/api/access/rules/${encodeURIComponent(operatorGroup)}`)

/** authentik group names, for suggestions in the rule editor. */
export const listGroups = () =>
  request<{ groups: string[] }>('GET', '/api/groups').then((res) => res.groups)

export const createUser = (input: CreateUserInput) => request<User>('POST', '/api/users', input)

export const updateUser = (id: number, input: Partial<UserInput>) =>
  request<User>('PATCH', `/api/users/${id}`, input)

export const deleteUser = (id: number) => request<void>('DELETE', `/api/users/${id}`)

export const setPassword = (id: number, password: string) =>
  request<void>('POST', `/api/users/${id}/password`, { password })

export const me = () => request<Me>('GET', '/auth/me')

/** Ends the session and returns authentik's end-session URL, if it has one. */
export const logout = () => request<{ logout_url?: string }>('POST', '/auth/logout')
