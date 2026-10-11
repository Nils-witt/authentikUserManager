export type UserType = 'internal' | 'external' | 'service_account' | 'internal_service_account'

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
  /** Name of the user's primary group, one of their groups; empty when none is set. */
  primary_group: string
  /** Whether the operator may change the user: only the operators managing their primary group may. */
  changeable: boolean
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

/** A group visible to every signed-in user; its members stay hidden. */
export interface PublicGroup {
  pk: string
  name: string
  /** Name of the parent group; empty or null for a top-level group. */
  parent_name: string | null
  /** The signed-in user was a member at login; set in the list of visible groups only. */
  member?: boolean
}

/** An authentik group, as access administrators see it. */
export interface Group extends PublicGroup {
  /** Members are authentik superusers. */
  is_superuser: boolean
  /** Every signed-in user may see the group's name, but not its members. */
  visible: boolean
}

/** One page of a list. */
export interface Page<T> {
  pagination: Pagination
  results: T[]
}

export interface UserInput {
  username: string
  name: string
  email: string
  is_active: boolean
  path: string
}

export interface CreateUserInput extends UserInput {
  /** Group the new user joins and their primary group; required for operators with restricted access. */
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
  /** Password recovery emails can be sent. */
  recovery_email: boolean
}

/** Members of operator_group may manage members of target_groups ('*': all users). */
export interface AccessRule {
  operator_group: string
  target_groups: string[]
}

export const WILDCARD = '*'

/** What an operator did, as recorded in the audit log. */
export type AuditAction =
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'user.group_added'
  | 'user.group_removed'
  | 'user.primary_group_changed'
  | 'user.recovery_email_sent'
  | 'user.access_denied'
  | 'access_rule.saved'
  | 'access_rule.deleted'
  | 'group.renamed'
  | 'group.visibility_changed'
  | 'group.join_requested'
  | 'group.join_withdrawn'
  | 'group.join_approved'
  | 'group.join_rejected'

/** One record in the audit log. */
export interface AuditEntry {
  id: number
  time: string
  /** Username of the operator. */
  actor: string
  action: AuditAction
  /** Username of the affected user, operator group of the affected rule, or name of the affected group. */
  target: string
  details: Record<string, string>
}

/** A page of the audit log, newest first. */
export interface AuditPage {
  entries: AuditEntry[]
  /** Pass as `before` to load the next page; absent on the last page. */
  next?: number
}

export type JoinRequestStatus = 'pending' | 'approved' | 'rejected'

/** A user's request to join a visible group, decided by the operators managing the group. */
export interface JoinRequest {
  id: number
  group_pk: string
  /** Name of the group when the request was made. */
  group_name: string
  user_pk: number
  username: string
  /** The user's optional reason for joining. */
  message: string
  status: JoinRequestStatus
  created_at: string
  decided_at: string | null
  /** Username of the operator who decided; empty while pending. */
  decided_by: string
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

/** The source the server was built from. */
export interface BuildInfo {
  repository: string
  /** Full git commit hash; empty when unknown. */
  commit: string
  /** Release tag, e.g. "v1.2.3"; empty for untagged builds. */
  tag: string
  /** Built from a checkout with uncommitted changes. */
  modified: boolean
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
  /** Only active (true) or only inactive (false) users; all when omitted. */
  active?: boolean
}) {
  const q = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
  })
  if (params.search) q.set('search', params.search)
  if (params.path) q.set('path_startswith', params.path)
  if (params.active !== undefined) q.set('is_active', String(params.active))
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

/** Loads a page of the audit log; only access administrators may read it. */
export function listAudit(params: { search?: string; action?: AuditAction; before?: number }) {
  const q = new URLSearchParams()
  if (params.search) q.set('search', params.search)
  if (params.action) q.set('action', params.action)
  if (params.before) q.set('before', String(params.before))
  return request<AuditPage>('GET', `/api/audit?${q}`)
}

/** Up to 100 authentik group names, for suggestions; only access administrators may list them. */
export const listGroupNames = () =>
  request<Page<Group>>('GET', '/api/groups?page_size=100').then((res) =>
    res.results.map((g) => g.name),
  )

/** Loads a page of authentik groups, ordered by name; only access administrators may list them. */
export function listGroups(params: { search: string; page: number; pageSize: number }) {
  const q = new URLSearchParams({ page: String(params.page), page_size: String(params.pageSize) })
  if (params.search) q.set('search', params.search)
  return request<Page<Group>>('GET', `/api/groups?${q}`)
}

/** Loads a page of the groups visible to every signed-in user, ordered by name. */
export function listVisibleGroups(params: { search: string; page: number; pageSize: number }) {
  const q = new URLSearchParams({ page: String(params.page), page_size: String(params.pageSize) })
  if (params.search) q.set('search', params.search)
  return request<Page<PublicGroup>>('GET', `/api/groups/visible?${q}`)
}

/**
 * Renames a group or sets its visibility; omitted fields stay unchanged.
 * A rename renames the group in the access rules too.
 */
export const updateGroup = (pk: string, changes: { name?: string; visible?: boolean }) =>
  request<Group>('PATCH', `/api/groups/${encodeURIComponent(pk)}`, changes)

/** Loads a page of the direct members of a group, ordered by username. */
export function listGroupMembers(
  pk: string,
  params: { search: string; page: number; pageSize: number },
) {
  const q = new URLSearchParams({ page: String(params.page), page_size: String(params.pageSize) })
  if (params.search) q.set('search', params.search)
  return request<UserList>('GET', `/api/groups/${encodeURIComponent(pk)}/members?${q}`)
}

export const addGroupMember = (pk: string, userId: number) =>
  request<void>('PUT', `/api/groups/${encodeURIComponent(pk)}/members/${userId}`)

export const removeGroupMember = (pk: string, userId: number) =>
  request<void>('DELETE', `/api/groups/${encodeURIComponent(pk)}/members/${userId}`)

/** Asks to join a visible group; the operators managing it approve or reject the request. */
export const requestJoin = (groupPk: string, message: string) =>
  request<JoinRequest>('POST', `/api/groups/${encodeURIComponent(groupPk)}/join-requests`, {
    message,
  })

/** The signed-in user's own join requests, newest first. */
export const listMyJoinRequests = () =>
  request<{ requests: JoinRequest[] }>('GET', '/api/join-requests/mine').then((res) => res.requests)

/** Withdraws one of the signed-in user's pending join requests. */
export const withdrawJoinRequest = (id: number) =>
  request<void>('DELETE', `/api/join-requests/${id}`)

/** The pending join requests the signed-in operator may decide, newest first. */
export const listJoinRequests = () =>
  request<{ requests: JoinRequest[] }>('GET', '/api/join-requests').then((res) => res.requests)

/** Approves a pending join request, which adds the user to the group. */
export const approveJoinRequest = (id: number) =>
  request<JoinRequest>('POST', `/api/join-requests/${id}/approve`)

export const rejectJoinRequest = (id: number) =>
  request<JoinRequest>('POST', `/api/join-requests/${id}/reject`)

export const createUser = (input: CreateUserInput) => request<User>('POST', '/api/users', input)

export const updateUser = (id: number, input: Partial<UserInput>) =>
  request<User>('PATCH', `/api/users/${id}`, input)

/**
 * Replaces the user's groups with the named ones and sets their primary group, one of `groups`
 * ('' removes it). The primary group stays when `primaryGroup` is omitted; it cannot be left
 * without choosing another one.
 */
export const setUserGroups = (id: number, groups: string[], primaryGroup?: string) =>
  request<User>('PUT', `/api/users/${id}/groups`, { groups, primary_group: primaryGroup })

/** Emails the user a link to recover their account and set a new password. */
export const sendRecoveryEmail = (id: number) =>
  request<void>('POST', `/api/users/${id}/recovery-email`)

export const deleteUser = (id: number) => request<void>('DELETE', `/api/users/${id}`)

export const version = () => request<BuildInfo>('GET', '/api/version')

export const me = () => request<Me>('GET', '/auth/me')

/** Ends the session and returns authentik's end-session URL, if it has one. */
export const logout = () => request<{ logout_url?: string }>('POST', '/auth/logout')
