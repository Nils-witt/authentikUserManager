# authentik-manager
This app it not affiliated with the [authentik](https://goauthentik.io) project.

A small web app for managing users in an [authentik](https://goauthentik.io) instance.

- `cmd/authentik-manager`: Go API server. It proxies a narrow, validated set of user operations to the authentik API (`/api/v3/core/users/`). It serves the frontend, which is embedded into the binary.
- `internal/auth`: OIDC login against authentik (authorization code + PKCE) with server-side sessions.
- `internal/authentik`: a minimal typed client for authentik's user, group and token endpoints.
- `internal/server`: HTTP handlers, input validation and error mapping.
- `internal/web`: embeds the built frontend (`internal/web/dist`, written by Vite).
- `frontend/`: React + TypeScript (Vite) UI.

## Features

List and search users (paginated), filter them by active or inactive, browse them by folder (path), create, edit (username, name, email, path, type, active, groups and [primary group](#primary-groups)), activate/deactivate, delete, and send a password recovery email. Access administrators can also list the authentik [groups](#groups), create and rename them, and add or remove their members. Users can [request to join](#join-requests) visible groups, and the operators managing a group approve or reject the requests. Users can issue [client certificates](#client-certificates) for their own account, which they and their operators can revoke. Operators also manage [service accounts](#service-accounts) with their tokens, certificates and API keys, with which service accounts renew and revoke their own certificates. Group-based access rules limit which users each operator may manage, Users are [notified](#notifications) in the app and by email about changes to their account. An [audit log](#audit-log) records every change.

## Configuration

Set these environment variables (see `.env.example`):

| Variable          | Required | Default          | Description                                             |
| ----------------- | -------- | ---------------- | ------------------------------------------------------- |
| `AUTHENTIK_URL`   | yes      |                  | Base URL of authentik, e.g. `https://sso.nils-witt.de`  |
| `AUTHENTIK_TOKEN` | yes      |                  | API token (Directory → Tokens, intent "API")            |
| `LISTEN_ADDR`     | no       | `127.0.0.1:8080` | Address the server listens on                           |
| `STATIC_DIR`      | no       |                  | Serve the frontend from this directory instead of the embedded build |
| `AUTHENTIK_RECOVERY_EMAIL_STAGE` | no |              | UUID of the email stage that sends [recovery emails](#password-recovery-emails); disabled when unset |
| `OIDC_ISSUER`     | yes      |                  | Issuer of the OIDC provider, `https://<host>/application/o/<slug>/` |
| `OIDC_CLIENT_ID`  | yes      |                  | Client ID of the provider                               |
| `OIDC_CLIENT_SECRET` | yes   |                  | Client secret of the provider                           |
| `OIDC_REDIRECT_URL`  | yes   |                  | Public callback URL of this app, ending in `/auth/callback` |
| `DATABASE_URL`    | yes      |                  | PostgreSQL URL for the access rules, the join requests and the audit log, e.g. `postgres://am:secret@db:5432/am` |
| `AUDIT_RETENTION_DAYS` | no |                | Days to keep [audit log](#audit-log) entries; kept forever when unset |
| `ACCESS_ADMIN_GROUPS` | yes  |                  | Comma-separated authentik groups with full access that may edit the [access rules](#access-rules) |
| `CA_CERT_FILE`    | no       |                  | PEM file of the CA certificate that signs [client certificates](#client-certificates), optionally followed by the certificates above it; disabled when unset |
| `CA_KEY_FILE`     | with `CA_CERT_FILE` |       | PEM file of the CA's unencrypted private key (PKCS#8, PKCS#1 or SEC 1) |
| `CERT_VALIDITY_DAYS` | no    | `365`            | Days client certificates are valid (at most 3650, and never beyond the CA's expiry) |
| `CERT_CRL_URL`    | no       |                  | Public URL of `/pki/crl`, embedded in client certificates as their CRL distribution point |
| `CERT_CRL_VALIDITY_DAYS` | no | `30`             | Days each CRL is valid until its next update (at most 365) |
| `CERT_USER_CN_SUFFIX` | no   |                  | Appended to the username in the common name of user certificates, e.g. `@example.com` for `ann@example.com` |
| `CERT_SERVICE_ACCOUNT_CN_SUFFIX` | no |         | Appended to the username in the common name of service account certificates |
| `SMTP_HOST`       | no       |                  | SMTP server that emails [notifications](#notifications); in the app only when unset |
| `SMTP_TLS`        | no       | `starttls`       | `starttls`, `tls` (implicit TLS) or `none` (only for a server on localhost) |
| `SMTP_PORT`       | no       | by `SMTP_TLS`    | SMTP port; 587 for `starttls`, 465 for `tls`, 25 for `none` |
| `SMTP_USERNAME`   | no       |                  | SMTP username; no authentication when unset             |
| `SMTP_PASSWORD`   | no       |                  | SMTP password                                           |
| `SMTP_FROM`       | with `SMTP_HOST` |          | Sender of notification emails, e.g. `authentik Manager <noreply@example.com>` |

The token's user needs permission to view, add, change and delete users, to view and change groups, and to add users to groups and remove them. To manage the tokens of [service accounts](#service-accounts) it must be a superuser: authentik assigns tokens created by other users to themselves.

## Password recovery emails

Operators can send a user an email with a link to set a new password (the envelope icon in
the user list). authentik sends it through its recovery API, so it needs:

- an **email stage** (Flows and Stages → Stages); set its UUID as `AUTHENTIK_RECOVERY_EMAIL_STAGE`,
- a **recovery flow** on the brand (System → Brands), which the link opens,
- the permission "Can reset user password" for the token's user,
- an email address on the target user.

When `AUTHENTIK_RECOVERY_EMAIL_STAGE` is unset the action is hidden. Operators can send the
email to every user they may manage.

## Client certificates

When `CA_CERT_FILE` and `CA_KEY_FILE` are set, every signed-in internal user can issue X.509
client certificates for their own account under **My certificates**. The CA certificate must
be a CA allowed to sign certificates and CRLs (key usages `keyCertSign` and `cRLSign`).
Certificates have the username as common name, followed by `CERT_USER_CN_SUFFIX` (or
`CERT_SERVICE_ACCOUNT_CN_SUFFIX` for service accounts) when set, the user's authentik UUID as a
`urn:uuid:<uuid>` URI SAN, and the `clientAuth` extended key usage. Usernames can be reused
after a user is deleted or renamed, so relying parties should identify users by the UUID. The
email address is not included, since users and operators can change it without verification.
Users may choose a **common name prefix** for their own certificates (1 to 32 letters, digits,
dots, hyphens and underscores), giving the common name `prefix+username`, e.g.
`adm+ann@example.com`. Service account certificates take none, and a prefix is refused when an
authentik account is named `prefix+username` itself. Since the prefix is chosen freely, relying
parties should not trust the common name alone either.

- **Generate key**: the server generates an ECDSA P-256 key and bundles it with the
  certificate and the CA chain, as a password-protected PKCS#12 file (`.p12`) or as PEM. The
  bundle is held in memory only and can be downloaded **once, within 15 minutes**; the server
  forgets it afterwards, and a restart discards it. The key is never stored.
- **Sign CSR**: the user keeps their key and pastes a certificate signing request (RSA ≥ 2048
  bits, ECDSA P-256/P-384/P-521 or Ed25519). The subject the CSR asks for is ignored.

Nobody can issue certificates for other users, not even access administrators. Operators who
may change a user (see [primary groups](#primary-groups)) can list the user's certificates
(the shield icon in the user list) and revoke them; users can revoke their own. Deleting,
deactivating or renaming a user through this application revokes all of their certificates;
reactivating the user does not restore them. Changes made directly in authentik bypass this,
so revoke the certificates here as well. Access administrators can review every issued
certificate under **Issued certificates**, download it (the certificate only, never its key;
not for certificates issued before this was added) and revoke it, including the certificates of
deleted users. Revoked
certificates are listed in the CRL at `/pki/crl` (as PEM at `/pki/crl.pem`) until they expire; each
CRL is valid for `CERT_CRL_VALIDITY_DAYS` (30 by default). The CA chain is at
`/pki/ca.pem`. All are public, so relying parties can fetch them without a login.

Access administrators can also **import** certificates the CA signed outside this application
(for example with openssl, before it was used), under **Issued certificates → Import**, so they
are listed and can be revoked through the CRL. Paste or load PEM certificates, up to 100 at once;
each is assigned to the active internal user or service account named by its common name (without
`CERT_USER_CN_SUFFIX` or `CERT_SERVICE_ACCOUNT_CN_SUFFIX`, when it ends in one, and without a
`prefix+` unless an account is named with it), and a
certificate holding a `urn:uuid:` URI SAN must match that account's UUID. Expired certificates,
certificates of other CAs and already recorded serial numbers are rejected, CA certificates are
skipped and private keys ignored. With **Revoke the imported certificates right away** checked,
they are recorded as revoked by the importing administrator, so the CRL lists them at once, e.g.
to withdraw certificates signed before this application was used; this cannot be undone. With
**Import certificates without a matching account**
checked, certificates whose account is missing, inactive or has another UUID, or that have no
common name, are imported **assigned to no user** instead; they are listed as *Unassigned* and
can only be downloaded and revoked by access administrators. **Assign** assigns such a
certificate to an active internal user or service account entered by the administrator, by
default the one named by its common name; the certificate keeps its common name, so relying
parties that identify certificates by it still see the original name. Imported certificates show the
importing administrator as issuer, are revoked with their user like issued ones, and can be
downloaded.

For development, `make example-ca` (or `scripts/example-ca.sh [dir] [common name] [days]`)
creates a self-signed ECDSA P-256 CA in `ca/`, which git ignores; then set
`CA_CERT_FILE=ca/ca.crt` and `CA_KEY_FILE=ca/ca.key`. Use a properly protected CA in production.

## Service accounts

authentik service accounts (type `service_account`) are listed under **Service accounts**. They
have no password and never sign in to this application; programs authenticate as them with tokens
or client certificates. Internal service accounts, which authentik manages for outposts, are never
shown.

- They follow the [access rules](#access-rules) and [primary groups](#primary-groups) of users:
  operators see the service accounts in their target groups, and only the operators managing a
  service account's primary group may change it, its tokens and its certificates. Restricted
  operators must pick one of their target groups when creating one. Only access administrators
  delete them.
- **Tokens**: API tokens (for the authentik API) and app passwords (e.g. for LDAP), optionally
  expiring. The key is shown once, when the token is created; the app never stores or logs it.
  Tokens authentik manages itself cannot be deleted here. Deactivating a service account makes
  authentik reject its tokens; deleting it deletes them.
- **Certificates**: the operators who may change a service account issue [client
  certificates](#client-certificates) for it, like users do for themselves. A generated key can be
  downloaded once, by the operator who issued the certificate. Renaming, deactivating or deleting
  the service account revokes its certificates, as for users.
- **API keys**: when certificates are configured, the same operators create API keys with which
  the service account itself issues and revokes its certificates through the [service
  API](#service-api), optionally expiring. The key is shown once; only its SHA-256 hash is stored.
  Deleting a key rejects it at once; deactivating the service account rejects its keys, and
  deleting it deletes them.

The API mirrors the user routes under `/api/service-accounts` (`GET`, `POST`, `GET`/`PATCH`/`DELETE
/{id}`, `PUT /{id}/groups`), plus `GET` and `POST /api/service-accounts/{id}/tokens` (body
`{"intent": "api"|"app_password", "description": "...", "expires": "<RFC 3339>"|null}`, returning
`{token, key}`), `DELETE /api/service-accounts/{id}/tokens/{identifier}`, `GET` and `POST
/api/service-accounts/{id}/certificates` (as `/api/certificates/mine`) and `POST
/api/service-accounts/{id}/certificates/{serial}/revoke`. Generated keys are downloaded from
`/api/certificates/mine/{serial}/download` by the issuing operator. API keys are listed and
created with `GET` and `POST /api/service-accounts/{id}/api-keys` (body `{"description": "...",
"expires": "<RFC 3339>"|null}`, returning `{api_key, key}`) and deleted with `DELETE
/api/service-accounts/{id}/api-keys/{keyID}`.

### Service API

Programs running as a service account renew and revoke its certificates under `/service-api/v1/`,
authenticated with an API key instead of a session (`Authorization: Bearer amk_…`). The service
account must be active. The server never generates keys here: the program sends a CSR and keeps
its private key.

| Method | Path                                           | Body                                                         |
| ------ | ---------------------------------------------- | ------------------------------------------------------------ |
| GET    | `/service-api/v1/certificates`                 | the service account's certificates: `{certificates}`         |
| POST   | `/service-api/v1/certificates`                 | `{csr}`; returns `{certificate, certificate_pem, chain_pem}` |
| POST   | `/service-api/v1/certificates/{serial}/revoke` | revokes a certificate of the service account; returns it     |

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout client.key -out client.csr -subj /CN=ignored
jq -Rs '{csr: .}' client.csr | curl -sS -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' -d @- https://<app-host>/service-api/v1/certificates
curl -sS -X POST -H "Authorization: Bearer $API_KEY" \
  https://<app-host>/service-api/v1/certificates/$SERIAL/revoke
```

The subject of the CSR is ignored; the certificate names the service account like the ones
operators issue. Requests without a valid key get 401. Changes made through the service API are
audited with the service account as the actor and the key's ID.

## Access rules

Access rules limit which users each operator may see and manage, based on the groups of
the target user. Access administrators edit them in the UI (the **Access rules** tab);
they are stored in PostgreSQL.

- **Access administrators** are the members of `ACCESS_ADMIN_GROUPS`. They always have full
  access and are the only ones who may edit the rules, so nobody can lock themselves out.
  They are also the only ones who may delete users (other operators can deactivate them)
  and manage the [groups](#groups); everyone else only sees the groups marked visible.
- A **rule** names an operator group (from the `groups` claim at login) and the target groups
  its members may manage. An operator gets the union of the target groups of all their groups.
- An operator may manage a user only if the user is a direct member of one of the target groups.
  Members of inherited (parent) groups are not matched.
- The target "all users" (`*`) grants access to every user. Superusers are only visible to
  operators with it and to access administrators.
- Access administrators can mark a user or service account **hidden**. Only access
  administrators see hidden users, even if a rule grants one of the user's groups or all
  users (`*`). Users still see their own account. Hidden is stored in authentik as the user
  attribute `authentik_manager_hidden: true`. Users without the attribute are not hidden.
  The list leaves hidden users out using authentik's `attributes` filter with an `__isnull`
  lookup.
- Operators without a matching rule see no users.
- Users outside an operator's scope are hidden from the list and return 404 on every
  per-user route.
- Restricted operators must pick one of their target groups when creating a user.
  Groups that grant superuser rights are refused.
- Rule changes apply immediately. An operator's own groups are read at login, so changes to
  their membership apply after the next login.

The schema is created and migrated automatically at startup
(`internal/store/migrations`, applied with golang-migrate).

## Groups

Access administrators manage the authentik groups in the UI (**Groups** in the toolbar):
search and page through them, create a group, rename it, make it visible to everyone, and add or
remove its direct members. Other operators change the groups of the users they manage in the user
dialog instead.

Every signed-in user, even one who may not manage any users, can open **Groups** to see the
groups marked visible. They see each group's name and parent only, never its members, its
attributes or whether it grants superuser rights.

- Visibility is stored in authentik as the group attribute `authentik_manager_visible: true`,
  so it can also be set there. Only the JSON value `true` counts. authentik replaces all
  attributes of a group on update, so the app reads them, changes only this key and writes
  them back; a change made to other attributes in authentik at the same moment can be lost.

- Access rules match groups by name, so renaming a group renames it in every rule too, in one
  transaction. If the rules cannot be updated, the group gets its previous name back.
- An operator's groups are read at login, so members of a renamed operator group must sign in
  again before the renamed rule applies to them.
- Groups named in `ACCESS_ADMIN_GROUPS` cannot be renamed, and no group can be renamed to one of
  those names, to `*`, or to the name of another group.
- Only access administrators can create groups. A new group has no members and never grants
  superuser rights. Its name must not be `*` or the name of another group; it may be one named in
  `ACCESS_ADMIN_GROUPS`, so such a group can be set up from here.
- Adding a user to a group that grants superuser rights asks for confirmation first.

The API for access administrators is `GET /api/groups` (`search`, `page`, `page_size`),
`POST /api/groups` (body `{"name": "...", "visible": true, "path": "..."}`, returns 201),
`GET` and `PATCH /api/groups/{pk}` (body `{"name": "...", "visible": true}`, both optional),
`GET /api/groups/{pk}/members` (`search`, `page`, `page_size`), and `PUT` and
`DELETE /api/groups/{pk}/members/{user id}`. Removing a user from their primary group returns 409. Every signed-in user may call
`GET /api/groups/visible` (`search`, `page`, `page_size`); each group carries `member`, set when
the caller is a direct member.

## Primary groups

Every user can have one primary group, chosen in the user dialog from the groups they are a
direct member of. The user list shows it first, marked "(primary)".

- It is stored in authentik as the user attribute `authentik_manager_primary_group`, holding the
  group's primary key, so renaming the group keeps it. As with group visibility, the app reads the
  user's attributes, changes only this key and writes them back.
- A new user's group (the group restricted operators must choose) becomes their primary group.
- A user cannot be removed from their primary group, neither in the user dialog nor under
  **Groups**. Choose another primary group first, or in the same save in the user dialog.
- Only the operators managing a user's primary group may change the user: edit them, (de)activate
  them, change their groups, send them a recovery email or delete them. These are access
  administrators, operators with the "all users" rule, and operators whose rules name the group as
  a target. Other operators who manage one of the user's other groups still see the user, marked
  with a lock, and get 403 on these routes. Users without a primary group can be changed by every
  operator who may manage them.
- Restricted operators may only choose a primary group that is one of their target groups.
- If the user leaves the group in authentik directly, they have no primary group until another
  one is chosen.

## Join requests

Every signed-in user can ask to join a visible group (**Request to join** in **Groups**), with an
optional message of up to 500 characters. The request is stored in PostgreSQL until it is decided.

- The operators who may manage the group's members decide it: access administrators, operators
  with the "all users" rule, and operators whose rules name the group as a target. They see the
  pending requests under **Join requests** in the toolbar, with a count of the pending ones.
- Approving adds the user to the group in authentik. Rejecting leaves it unchanged; the user
  may ask again. Nobody decides their own request.
- Users see their pending requests in **Groups** and can withdraw them there.
- Only internal users can ask, only for visible groups, and not for groups that grant superuser
  rights. Each user has at most one pending request per group, and none for a group they are
  already in.
- Requests match groups by primary key, so renaming a group keeps them. They show the group's
  name as it was when the request was made. A request for a deleted group can still be rejected
  by the operators who managed the group under that name.
- If authentik cannot add the user, the request becomes pending again.

The API is `POST /api/groups/{pk}/join-requests` (body `{"message": "..."}`) and
`GET /api/join-requests/mine` and `DELETE /api/join-requests/{id}` for the requester, and
`GET /api/join-requests` (the pending requests the caller may decide) and
`POST /api/join-requests/{id}/approve` or `/reject` for the deciders.

## Notifications

Users are notified about changes to their own account, each with a header and a message:

| Category | Sent when |
| --- | --- |
| Profile changes | their username, name, email address, folder or active state changes, or they are added to or removed from groups, or their primary group changes |
| Certificates | a certificate is issued to them or revoked, also when their account is deactivated or renamed |
| Join requests | their request to join a group is granted or denied |
| Notification settings | their notification settings are saved; always sent and cannot be turned off |

Notifications appear behind the bell in the toolbar and are kept until the user deletes
them. When `SMTP_HOST` is set they are emailed too; a changed email address is told about
the change as well. Each user chooses per category and channel which notifications they
receive (**Notifications → Settings**). Only internal users receive notifications; service
accounts do not. Further delivery channels implement `notification.NotificationReceiver`
and are passed to `notification.NewNotifier` in `cmd/authentik-manager`.

The API, for the signed-in user's own notifications: `GET /api/notifications` (query
parameters `before`, `limit`), `GET /api/notifications/unread-count`,
`POST /api/notifications/{id}/read`, `POST /api/notifications/read-all`,
`DELETE /api/notifications/{id}`, `DELETE /api/notifications`, and
`GET`/`PUT /api/notifications/preferences` (body `{"preferences": {"profile": {"email": false}}}`).

## Audit log

Every change made through the app is recorded in PostgreSQL with the time, the operator,
the action, the affected user or rule, and details such as the changed fields or groups:
creating, updating and deleting users and service accounts, changing their groups and primary groups, sending recovery emails, issuing, importing, assigning and revoking certificates and downloading their keys, creating and deleting service account tokens and API keys (never their keys),
saving and deleting access rules, renaming groups and changing their visibility, requesting to join groups and withdrawing, approving and rejecting those requests, and requests for users outside the operator's scope.
Access administrators review it in the UI (**Audit log** in the toolbar) or through
`GET /api/audit` (query parameters `search`, `action`, `before`, `limit`).

Entries are also written to the application log (message `audit`). A change is not rolled
back when its entry cannot be stored; the failure is logged instead.

Entries are kept forever unless `AUDIT_RETENTION_DAYS` is set. Then entries older than that
are deleted at startup and every hour after.

## Setting up the login in authentik

1. **Applications → Providers → Create → OAuth2/OpenID Provider**
   - Client type: *Confidential*. Copy the client ID and secret.
   - Redirect URIs (strict): `https://<your-app>/auth/callback`, and for development `http://localhost:5173/auth/callback`.
   - **Signing Key: choose a certificate** (for example the self-signed default). Without one, authentik signs ID tokens with HS256, which this app rejects.
   - Scopes: keep the defaults (`openid`, `profile`, `email`). The `profile` scope supplies the `groups` claim.
2. **Applications → Applications → Create**, slug e.g. `authentik-manager`, using the provider above.
   The issuer is then `https://sso.nils-witt.de/application/o/authentik-manager/`.
3. Optional but recommended: bind a group policy to the application, so authentik itself refuses other users.

## Development

```sh
make dev-db                      # PostgreSQL in Docker on 127.0.0.1:5432 (compose.yaml)
set -a; source .env; set +a      # copy .env.example to .env first
# for development, OIDC_REDIRECT_URL=http://localhost:5173/auth/callback
make dev-backend    # API on 127.0.0.1:8080
make dev-frontend   # Vite on http://localhost:5173, /api and /auth are proxied to the backend
make test           # go vet + go test -race (PostgreSQL tests are skipped)
make test-integration  # also runs the PostgreSQL tests against a temporary container
make lint           # golangci-lint (.golangci.yml) + oxlint + prettier --check
make fmt            # golangci-lint fmt + prettier --write (frontend/.prettierrc.json)
make vuln           # govulncheck
```

### Git hooks

Run `make hooks` once per clone. It enables `.githooks/pre-commit`, which runs
`golangci-lint` and `govulncheck` when Go files, `go.mod`/`go.sum` or `.golangci.yml`
are staged, and `oxlint` plus a Prettier check when files under `frontend/` are staged. You need
`golangci-lint` (v2) and `govulncheck` (`go install golang.org/x/vuln/cmd/govulncheck@latest`).
Skip the checks once with `git commit --no-verify`.

## Production build

```sh
make build                  # builds the frontend into internal/web/dist, then bin/authentik-manager
./bin/authentik-manager     # single self-contained binary, serves UI and API
```

The frontend is embedded with `//go:embed`, so `internal/web/dist` must exist before any
Go build, test or lint. The Makefile targets build it on first use; after changing
the frontend, run `make build` again.

## Security

- Users are filtered by the access rules on the server for every route; the UI only mirrors it.
  If the rules cannot be loaded, requests fail with 500 instead of falling back to more access.
- Every `/api/` route requires a login. The [service API](#service-api) requires the API key of an active service account instead and reads no cookies. The login uses authentik via OIDC: authorization code flow with PKCE, plus state and nonce checks. Any authentik user may log in; operators without an access rule see and manage no users.
- The browser only holds an opaque session cookie (`HttpOnly`, `SameSite=Lax`, and `Secure` with a `__Host-` prefix when served over https). ID and access tokens never reach the browser.
- Logging out of authentik also ends the app's sessions when the provider's **Back-Channel Logout URI** is set to `https://<app-host>/auth/backchannel-logout`. The app only accepts logout tokens signed by the provider for this client ID. It checks that the token is recent, carries the back-channel logout event and has no nonce. It ends the session with the token's `sid`. If the token or the session has no `sid`, it ends all sessions of the token's `sub`.
- Sessions live in memory for 8 hours. A restart logs everyone out, and you must run a single instance.
- Cross-origin state-changing requests are rejected (Go's `http.CrossOriginProtection`).
- Changes to users go to authentik with `AUTHENTIK_TOKEN`, not as the logged-in user. The app logs each change with the operator's username (`actor`).
- When serving over plain http on something other than localhost, put TLS in front of the app (reverse proxy).

## API

| Method | Path                       | Body                                                     |
| ------ | -------------------------- | -------------------------------------------------------- |
| GET    | `/api/access`              | the operator's scope: `{all, groups, admin}`             |
| GET    | `/api/access/rules`        | admins only: `{rules: [{operator_group, target_groups}]}` |
| PUT    | `/api/access/rules/{group}` | admins only: `{target_groups}` (creates or replaces)    |
| DELETE | `/api/access/rules/{group}` | admins only                                             |
| GET    | `/api/groups`              | admins only: authentik group names (max. 100), query `search` |
| GET    | `/api/users`               | internal users only; query: `search`, `page`, `page_size` (≤100), `ordering`, `path`, `path_startswith`, `is_active` |
| GET    | `/api/users/paths`         | all user folders: `{paths}`                              |
| POST   | `/api/users`               | `{username, name, email?, is_active?, path?, type?, group?}`; `type` must be `internal` |
| GET    | `/api/users/{id}`          | users carry `primary_group`: the name of their primary group, or empty, and `changeable`: whether the operator may change them ([primary groups](#primary-groups)) |
| PATCH  | `/api/users/{id}`          | any subset of the create fields                          |
| DELETE | `/api/users/{id}`          | admins only                                              |
| PUT    | `/api/users/{id}/groups`   | `{groups, primary_group?}`: the group names the user should be in, and the name of their primary group (one of `groups`; empty removes it, omitted keeps it). Restricted operators may only add or remove their target groups, and the user must keep one of them. The primary group cannot be removed |
| GET    | `/api/certificates/mine`   | the caller's certificates: `{certificates}`, each with `downloadable` while its key can be downloaded |
| POST   | `/api/certificates/mine`   | issues a certificate for the caller: `{csr}`, or `{format: "pem"}`, or `{format: "pkcs12", password}`; returns `{certificate, certificate_pem, chain_pem}` for a CSR, `{certificate, download_url, download_expires_at}` otherwise |
| GET    | `/api/certificates/mine/{serial}/download` | the generated key bundle, once, for the user who requested it (also an operator who issued it for a service account); 410 afterwards |
| GET    | `/api/users/{id}/certificates` | the user's certificates, for the user and the operators who may change them |
| POST   | `/api/users/{id}/certificates/{serial}/revoke` | revokes a certificate of the user |
| …      | `/api/service-accounts/…`  | see [service accounts](#service-accounts)                |
| GET    | `/api/certificates`        | access administrators only; the certificates of all users, newest first, paginated: `?search=` (username substring or serial prefix), `?status=active\|revoked\|expired`, `?page=`, `?page_size=` |
| GET    | `/api/certificates/{serial}/pem` | access administrators only; the certificate as PEM, without its key; 404 for certificates issued before certificates were stored |
| POST   | `/api/certificates/{serial}/revoke` | access administrators only; revokes a certificate of any user, including deleted ones |
| POST   | `/api/certificates/import` | access administrators only; imports certificates the CA signed elsewhere: `{pem, allow_unassigned}`; returns `{results}`, each `{serial, subject}` with `certificate` when imported (and `unassigned`, the reason, when assigned to no user; its `user_pk` is 0 and `username` empty) or `error` otherwise |
| POST   | `/api/certificates/{serial}/assign` | access administrators only; assigns an unassigned imported certificate to an active user or service account: `{username}`; returns the certificate; 409 when it is already assigned or there is no such active account |
| GET    | `/pki/crl`                 | DER certificate revocation list; no login required       |
| GET    | `/pki/crl.pem`             | The same revocation list as PEM; no login required       |
| GET    | `/pki/ca.pem`              | CA certificate chain; no login required                  |
| GET    | `/healthz`                 | no login required                                        |
| GET    | `/auth/login`              | starts the OIDC login                                     |
| GET    | `/auth/callback`           | OIDC redirect target                                      |
| GET    | `/auth/me`                 | the logged-in user, or 401                                |
| POST   | `/auth/logout`             | ends the session; returns `{logout_url}` for authentik    |
| POST   | `/auth/backchannel-logout` | OIDC Back-Channel Logout target for authentik (no login; requires a logout token signed by the provider) |

All `/api/` routes return 401 without a session. Errors are returned as `{"error": "...", "fields": {"field": ["message"]}}`.
