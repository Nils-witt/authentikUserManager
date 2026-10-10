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

export function listUsers(params: { search: string; page: number; pageSize: number }) {
  const q = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
  })
  if (params.search) q.set('search', params.search)
  return request<UserList>('GET', `/api/users?${q}`)
}

export const createUser = (input: UserInput) => request<User>('POST', '/api/users', input)

export const updateUser = (id: number, input: Partial<UserInput>) =>
  request<User>('PATCH', `/api/users/${id}`, input)

export const deleteUser = (id: number) => request<void>('DELETE', `/api/users/${id}`)

export const setPassword = (id: number, password: string) =>
  request<void>('POST', `/api/users/${id}/password`, { password })

export const me = () => request<Me>('GET', '/auth/me')

/** Ends the session and returns authentik's end-session URL, if it has one. */
export const logout = () => request<{ logout_url?: string }>('POST', '/auth/logout')
