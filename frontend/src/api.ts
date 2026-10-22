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
  /** Only access administrators see the user, whatever the access rules grant. */
  hidden: boolean
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
  /** Folder of the group, e.g. "school/classes"; empty at the top level. */
  path: string
  /** The signed-in user is a direct member; set in the group list of non-administrators only. */
  member?: boolean
  /** The signed-in user may request to join; set in the group list of non-administrators only. */
  joinable?: boolean
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
  /** Hides the user from operators who are not access administrators; only they may set it. */
  hidden?: boolean
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
  /** Users can issue client certificates for their own account. */
  certificates: boolean
  /** Suffixes appended to usernames in the common names of issued certificates, longest first. */
  certificate_cn_suffixes: string[]
  /** The suffix of user certificates alone, for previewing their common name. */
  certificate_user_cn_suffix: string
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
  | 'group.created'
  | 'group.renamed'
  | 'group.visibility_changed'
  | 'group.path_changed'
  | 'group.join_requested'
  | 'group.join_withdrawn'
  | 'group.join_approved'
  | 'group.join_rejected'
  | 'user.certificate_issued'
  | 'user.certificate_key_downloaded'
  | 'user.certificate_revoked'
  | 'user.certificate_imported'
  | 'user.certificate_assigned'
  | 'service_account.created'
  | 'service_account.updated'
  | 'service_account.deleted'
  | 'service_account.token_created'
  | 'service_account.token_deleted'

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

/** An authentik application a user may access. */
export interface Application {
  name: string
  slug: string
  /** The group the application is listed under in the user's library; may be empty. */
  group: string
  description: string
  publisher: string
  /** Absolute http(s) URL opening the application; empty when it has none. */
  launch_url: string
}

/**
 * Where a certificate's private key was created: by the server, by the user who sent a CSR, or
 * unknown for a certificate the CA signed elsewhere that an access administrator imported.
 */
export type KeySource = 'generated' | 'csr' | 'imported'

/** A client certificate issued to a user. Its private key is never stored. */
export interface Certificate {
  /** Lowercase hex serial number. */
  serial: string
  /** 0, with an empty username, for an imported certificate assigned to no user. */
  user_pk: number
  username: string
  /** Subject distinguished name, e.g. "CN=ann". */
  subject: string
  not_before: string
  not_after: string
  issued_at: string
  /** Username of the user who requested the certificate, or of the administrator who imported it. */
  issued_by: string
  key_source: KeySource
  revoked_at: string | null
  /** Username of the revoking user; empty while not revoked. */
  revoked_by: string
  /** The certificate itself is stored and can be downloaded; not for those issued before it was stored. */
  stored: boolean
}

/** The state of a certificate: usable, revoked, or expired without being revoked. */
export type CertificateStatus = 'active' | 'revoked' | 'expired'

/** A certificate of the signed-in user. */
export interface OwnCertificate extends Certificate {
  /** The generated key can still be downloaded, once. */
  downloadable: boolean
}

/** What to certify: the key of a CSR, or a new key downloaded in a format. */
export type IssueCertificateInput = (
  { csr: string } | { format: 'pem' } | { format: 'pkcs12'; password: string }
) & {
  /** Precedes the username in the common name, joined by "+"; own certificates only. */
  prefix?: string
}

/** The result of issuing a certificate. */
export interface IssuedCertificate {
  certificate: Certificate
  /** The certificate and the CA chain as PEM; set for a CSR. */
  certificate_pem?: string
  chain_pem?: string
  /** Set for a generated key, which can be downloaded once until download_expires_at. */
  download_url?: string
  download_expires_at?: string
}

/** What a service account token is for: the authentik API, or a password for applications. */
export type TokenIntent = 'api' | 'app_password'

/** A token of a service account; its key is only shown when it is created. */
export interface Token {
  identifier: string
  intent: TokenIntent
  description: string
  /** Primary key of the account the token authenticates as. */
  user: number
  /** False for a token that never expires. */
  expiring: boolean
  expires: string | null
  /** Set for tokens authentik manages itself, which cannot be deleted here. */
  managed: string | null
}

export interface CreateTokenInput {
  intent: TokenIntent
  description: string
  /** When the token expires (ISO 8601); null for a token that never expires. */
  expires: string | null
}

/** A new token with its key, which is not shown again. */
export interface CreatedToken {
  token: Token
  key: string
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
  const res = await send(method, path, body)
  if (res.status === 204) {
    return undefined as T
  }
  return (await res.json()) as T
}

/** Sends a request and throws an ApiError unless it succeeded. */
async function send(method: string, path: string, body?: unknown): Promise<Response> {
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
  return res
}

/** Filters and pages a list of users or service accounts. */
export interface AccountListParams {
  search: string
  page: number
  pageSize: number
  /** Only accounts in this folder or one of its subfolders. */
  path?: string
  /** Only active (true) or only inactive (false) accounts; all when omitted. */
  active?: boolean
}

function accountListQuery(params: AccountListParams) {
  const q = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
  })
  if (params.search) q.set('search', params.search)
  if (params.path) q.set('path_startswith', params.path)
  if (params.active !== undefined) q.set('is_active', String(params.active))
  return q
}

export const listUsers = (params: AccountListParams) =>
  request<UserList>('GET', `/api/users?${accountListQuery(params)}`)

/** Loads a page of the service accounts the operator may see. */
export const listServiceAccounts = (params: AccountListParams) =>
  request<UserList>('GET', `/api/service-accounts?${accountListQuery(params)}`)

/** Every distinct user path (folder), e.g. "users" or "users/staff". */
export const listUserPaths = () =>
  request<{ paths: string[] }>('GET', '/api/users/paths').then((res) => res.paths)

/** Every distinct service account path (folder), e.g. "service-accounts". */
export const listServiceAccountPaths = () =>
  request<{ paths: string[] }>('GET', '/api/service-accounts/paths').then((res) => res.paths)

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

interface GroupListParams {
  search: string
  /** Only the groups in exactly this folder; all groups when null. */
  path: string | null
  page: number
  pageSize: number
}

function groupListQuery(params: GroupListParams) {
  const q = new URLSearchParams({ page: String(params.page), page_size: String(params.pageSize) })
  if (params.search) q.set('search', params.search)
  if (params.path) q.set('path', params.path)
  return q
}

/** Loads a page of authentik groups, ordered by name; only access administrators may list them. */
export const listGroups = (params: GroupListParams) =>
  request<Page<Group>>('GET', `/api/groups?${groupListQuery(params)}`)

/**
 * Loads a page of the groups a non-administrator sees, ordered by name: those visible to
 * everyone, their own and those of the users they may see.
 */
export const listVisibleGroups = (params: GroupListParams) =>
  request<Page<PublicGroup>>('GET', `/api/groups/visible?${groupListQuery(params)}`)

/** Loads the group folders: of all groups for access administrators, of the groups they see for everyone else. */
export const listGroupPaths = () =>
  request<{ paths: string[] }>('GET', '/api/groups/paths').then((res) => res.paths)

/**
 * Creates a group without members; only access administrators may. The name must not be
 * taken, since access rules match groups by name.
 */
export const createGroup = (group: { name: string; visible: boolean; path: string }) =>
  request<Group>('POST', '/api/groups', group)

/**
 * Renames a group, sets its visibility or moves it to another folder (path);
 * omitted fields stay unchanged. A rename renames the group in the access rules too.
 */
export const updateGroup = (
  pk: string,
  changes: { name?: string; visible?: boolean; path?: string },
) => request<Group>('PATCH', `/api/groups/${encodeURIComponent(pk)}`, changes)

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

/** Creates a service account; it has no password, only tokens and certificates. */
export const createServiceAccount = (input: CreateUserInput) =>
  request<User>('POST', '/api/service-accounts', input)

export const updateServiceAccount = (id: number, input: Partial<UserInput>) =>
  request<User>('PATCH', `/api/service-accounts/${id}`, input)

/** Like setUserGroups, for a service account. */
export const setServiceAccountGroups = (id: number, groups: string[], primaryGroup?: string) =>
  request<User>('PUT', `/api/service-accounts/${id}/groups`, {
    groups,
    primary_group: primaryGroup,
  })

export const deleteServiceAccount = (id: number) =>
  request<void>('DELETE', `/api/service-accounts/${id}`)

/** The tokens of a service account, without their keys. */
export const listTokens = (id: number) =>
  request<{ tokens: Token[] }>('GET', `/api/service-accounts/${id}/tokens`).then(
    (res) => res.tokens,
  )

/** Creates a token for a service account; the result holds its key, which is not shown again. */
export const createToken = (id: number, input: CreateTokenInput) =>
  request<CreatedToken>('POST', `/api/service-accounts/${id}/tokens`, input)

export const deleteToken = (id: number, identifier: string) =>
  request<void>('DELETE', `/api/service-accounts/${id}/tokens/${encodeURIComponent(identifier)}`)

/** The certificates of a service account; `downloadable` while the signed-in operator can download a key. */
export const listServiceAccountCertificates = (id: number) =>
  request<{ certificates: OwnCertificate[] }>(
    'GET',
    `/api/service-accounts/${id}/certificates`,
  ).then((res) => res.certificates)

/** Issues a certificate for a service account; the issuing operator downloads a generated key. */
export const issueServiceAccountCertificate = (id: number, input: IssueCertificateInput) =>
  request<IssuedCertificate>('POST', `/api/service-accounts/${id}/certificates`, input)

export const revokeServiceAccountCertificate = (id: number, serial: string) =>
  request<Certificate>(
    'POST',
    `/api/service-accounts/${id}/certificates/${encodeURIComponent(serial)}/revoke`,
  )

/** The signed-in user's own certificates, newest first. */
export const listMyCertificates = () =>
  request<{ certificates: OwnCertificate[] }>('GET', '/api/certificates/mine').then(
    (res) => res.certificates,
  )

/** Issues a certificate for the signed-in user's own account. */
export const issueCertificate = (input: IssueCertificateInput) =>
  request<IssuedCertificate>('POST', '/api/certificates/mine', input)

/**
 * Downloads the generated key of a certificate the signed-in user requested, for themselves or a
 * service account; the server forgets it afterwards.
 */
export const downloadCertificateKey = (serial: string) =>
  send('GET', `/api/certificates/mine/${encodeURIComponent(serial)}/download`).then((res) =>
    res.blob(),
  )

/** The certificates of a user the operator may change, without their keys. */
export const listUserCertificates = (userId: number) =>
  request<{ certificates: Certificate[] }>('GET', `/api/users/${userId}/certificates`).then(
    (res) => res.certificates,
  )

/** Lists the applications the user may access, as the policies bound to them decide. */
export const listUserApplications = (userId: number) =>
  request<{ applications: Application[] }>('GET', `/api/users/${userId}/applications`).then(
    (res) => res.applications,
  )

/** Revokes a certificate of the user; it is listed in the CRL from then on. */
export const revokeCertificate = (userId: number, serial: string) =>
  request<Certificate>(
    'POST',
    `/api/users/${userId}/certificates/${encodeURIComponent(serial)}/revoke`,
  )

/** Filters the certificates of all users. */
export interface CertificateListParams {
  /** Matches the username by substring, or the serial number by prefix. */
  search: string
  status: CertificateStatus | null
  page: number
  pageSize: number
}

/** Loads a page of the certificates of all users, newest first; only access administrators may list them. */
export function listCertificates(params: CertificateListParams) {
  const q = new URLSearchParams({ page: String(params.page), page_size: String(params.pageSize) })
  if (params.search) q.set('search', params.search)
  if (params.status) q.set('status', params.status)
  return request<Page<Certificate>>('GET', `/api/certificates?${q}`)
}

/** Downloads a certificate of any user as PEM, without its key; only for access administrators. */
export const downloadCertificate = (serial: string) =>
  send('GET', `/api/certificates/${encodeURIComponent(serial)}/pem`).then((res) => res.text())

/** Revokes a certificate of any user, including deleted ones; only for access administrators. */
export const revokeAnyCertificate = (serial: string) =>
  request<Certificate>('POST', `/api/certificates/${encodeURIComponent(serial)}/revoke`)

/**
 * Assigns an imported certificate that belongs to no user to the active user or service account
 * named username; only for access administrators.
 */
export const assignCertificate = (serial: string, username: string) =>
  request<Certificate>('POST', `/api/certificates/${encodeURIComponent(serial)}/assign`, {
    username,
  })

/** The outcome of importing one certificate. */
export interface ImportResult {
  serial: string
  subject: string
  /** The record of the imported certificate; absent when `error` is set. */
  certificate?: Certificate
  /** Why the certificate was imported without a user; absent when it was assigned to one. */
  unassigned?: string
  /** Why the certificate was not imported. */
  error?: string
}

/** How certificates are imported. */
export interface ImportOptions {
  /** Import those without a matching account without a user instead of rejecting them. */
  allowUnassigned: boolean
  /** Record them as revoked right away, so the CRL lists them. */
  revoke: boolean
}

/**
 * Imports PEM certificates the CA signed elsewhere, so they can be listed and revoked; only for
 * access administrators. Each is assigned to the account its common name names.
 */
export const importCertificates = (pem: string, options: ImportOptions) =>
  request<{ results: ImportResult[] }>('POST', '/api/certificates/import', {
    pem,
    allow_unassigned: options.allowUnassigned,
    revoke: options.revoke,
  }).then((res) => res.results)

export const version = () => request<BuildInfo>('GET', '/api/version')

export const me = () => request<Me>('GET', '/auth/me')

/** Ends the session and returns authentik's end-session URL, if it has one. */
export const logout = () => request<{ logout_url?: string }>('POST', '/auth/logout')

/** What a notification is about. */
export type NotificationCategory = 'profile' | 'certificate' | 'join_request' | 'settings'

/** A message to the signed-in user about a change to their account. */
export interface Notification {
  id: number
  category: NotificationCategory
  header: string
  message: string
  created_at: string
  /** Null while unread. */
  read_at: string | null
}

/** A page of the signed-in user's notifications, newest first. */
export interface NotificationPage {
  notifications: Notification[]
  /** Pass as `before` to load the next page; absent on the last page. */
  next?: number
  /** How many of all the user's notifications are unread. */
  unread: number
}

/** A way notifications reach the user: "in_app", or a delivery system such as "email". */
export interface NotificationChannel {
  name: string
  label: string
}

/** Whether the user receives the notifications of a category, per category and channel. */
export type NotificationPreferences = Record<NotificationCategory, Record<string, boolean>>

/** The signed-in user's notification preferences and what they choose between. */
export interface NotificationSettings {
  channels: NotificationChannel[]
  categories: { name: NotificationCategory; label: string; mandatory: boolean }[]
  preferences: NotificationPreferences
}

/** Loads a page of the signed-in user's notifications, newest first. */
export function listNotifications(params: { before?: number } = {}) {
  const q = new URLSearchParams()
  if (params.before) q.set('before', String(params.before))
  return request<NotificationPage>('GET', `/api/notifications?${q}`)
}

/** Counts the signed-in user's unread notifications. */
export const countUnreadNotifications = () =>
  request<{ unread: number }>('GET', '/api/notifications/unread-count').then((res) => res.unread)

export const markNotificationRead = (id: number) =>
  request<void>('POST', `/api/notifications/${id}/read`)

export const markAllNotificationsRead = () => request<void>('POST', '/api/notifications/read-all')

export const deleteNotification = (id: number) =>
  request<void>('DELETE', `/api/notifications/${id}`)

export const deleteAllNotifications = () => request<void>('DELETE', '/api/notifications')

export const notificationSettings = () =>
  request<NotificationSettings>('GET', '/api/notifications/preferences')

/** Saves the signed-in user's preferences; they are always notified of the change. */
export const putNotificationPreferences = (preferences: NotificationPreferences) =>
  request<NotificationSettings>('PUT', '/api/notifications/preferences', { preferences })
