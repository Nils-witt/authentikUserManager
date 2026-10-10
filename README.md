# authentik-manager
This app it not affiliated with the [authentik](https://goauthentik.io) project.

A small web app for managing users in an [authentik](https://goauthentik.io) instance.

- `cmd/authentik-manager`: Go API server. It proxies a narrow, validated set of user operations to the authentik API (`/api/v3/core/users/`). It serves the frontend, which is embedded into the binary.
- `internal/auth`: OIDC login against authentik (authorization code + PKCE) with server-side sessions.
- `internal/authentik`: a minimal typed client for authentik's user endpoints.
- `internal/server`: HTTP handlers, input validation and error mapping.
- `internal/web`: embeds the built frontend (`internal/web/dist`, written by Vite).
- `frontend/`: React + TypeScript (Vite) UI.

## Features

List and search users (paginated), filter them by active or inactive, browse them by folder (path), create, edit (username, name, email, path, type, active), activate/deactivate, delete, and send a password recovery email. Group-based access rules limit which users each operator may manage.

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
| `DATABASE_URL`    | yes      |                  | PostgreSQL URL for the access rules, e.g. `postgres://am:secret@db:5432/am` |
| `ACCESS_ADMIN_GROUPS` | yes  |                  | Comma-separated authentik groups with full access that may edit the [access rules](#access-rules) |

The token's user needs permission to view, add, change and delete users, and to add users to groups and remove them.

## Password recovery emails

Operators can send a user an email with a link to set a new password (the envelope icon in
the user list). authentik sends it through its recovery API, so it needs:

- an **email stage** (Flows and Stages → Stages); set its UUID as `AUTHENTIK_RECOVERY_EMAIL_STAGE`,
- a **recovery flow** on the brand (System → Brands), which the link opens,
- the permission "Can reset user password" for the token's user,
- an email address on the target user.

When `AUTHENTIK_RECOVERY_EMAIL_STAGE` is unset the action is hidden. Operators can send the
email to every user they may manage.

## Access rules

Access rules limit which users each operator may see and manage, based on the groups of
the target user. Access administrators edit them in the UI (**Access rules** in the toolbar);
they are stored in PostgreSQL.

- **Access administrators** are the members of `ACCESS_ADMIN_GROUPS`. They always have full
  access and are the only ones who may edit the rules, so nobody can lock themselves out.
  They are also the only ones who may delete users; other operators can deactivate them.
- A **rule** names an operator group (from the `groups` claim at login) and the target groups
  its members may manage. An operator gets the union of the target groups of all their groups.
- An operator may manage a user only if the user is a direct member of one of the target groups.
  Members of inherited (parent) groups are not matched.
- The target "all users" (`*`) grants access to every user. Superusers are only visible to
  operators with it and to access administrators.
- Operators without a matching rule see no users.
- Users outside an operator's scope are hidden from the list and return 404 on every
  per-user route.
- Restricted operators must pick one of their target groups when creating a user.
  Groups that grant superuser rights are refused.
- Rule changes apply immediately. An operator's own groups are read at login, so changes to
  their membership apply after the next login.

The schema is created and migrated automatically at startup
(`internal/store/migrations`, applied with golang-migrate).

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
- Every `/api/` route requires a login. The login uses authentik via OIDC: authorization code flow with PKCE, plus state and nonce checks. Any authentik user may log in; operators without an access rule see and manage no users.
- The browser only holds an opaque session cookie (`HttpOnly`, `SameSite=Lax`, and `Secure` with a `__Host-` prefix when served over https). ID and access tokens never reach the browser.
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
| GET    | `/api/users/{id}`          |                                                          |
| PATCH  | `/api/users/{id}`          | any subset of the create fields                          |
| DELETE | `/api/users/{id}`          | admins only                                              |
| PUT    | `/api/users/{id}/groups`   | `{groups}`: the group names the user should be in. Restricted operators may only add or remove their target groups, and the user must keep one of them |
| GET    | `/healthz`                 | no login required                                        |
| GET    | `/auth/login`              | starts the OIDC login                                     |
| GET    | `/auth/callback`           | OIDC redirect target                                      |
| GET    | `/auth/me`                 | the logged-in user, or 401                                |
| POST   | `/auth/logout`             | ends the session; returns `{logout_url}` for authentik    |

All `/api/` routes return 401 without a session. Errors are returned as `{"error": "...", "fields": {"field": ["message"]}}`.
