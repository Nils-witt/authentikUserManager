# authentik-manager

A small web app for managing users in an [authentik](https://goauthentik.io) instance.

- `cmd/authentik-manager`: Go API server. It proxies a narrow, validated set of user operations to the authentik API (`/api/v3/core/users/`). It can also serve the built frontend.
- `internal/auth`: OIDC login against authentik (authorization code + PKCE) with server-side sessions.
- `internal/authentik`: a minimal typed client for authentik's user endpoints.
- `internal/server`: HTTP handlers, input validation and error mapping.
- `frontend/`: React + TypeScript (Vite) UI.

## Features

List and search users (paginated), create, edit (username, name, email, path, type, active), activate/deactivate, set password, delete.

## Configuration

Set these environment variables (see `.env.example`):

| Variable          | Required | Default          | Description                                             |
| ----------------- | -------- | ---------------- | ------------------------------------------------------- |
| `AUTHENTIK_URL`   | yes      |                  | Base URL of authentik, e.g. `https://sso.nils-witt.de`  |
| `AUTHENTIK_TOKEN` | yes      |                  | API token (Directory → Tokens, intent "API")            |
| `LISTEN_ADDR`     | no       | `127.0.0.1:8080` | Address the server listens on                           |
| `STATIC_DIR`      | no       |                  | Serve the built frontend from this directory            |
| `OIDC_ISSUER`     | yes      |                  | Issuer of the OIDC provider, `https://<host>/application/o/<slug>/` |
| `OIDC_CLIENT_ID`  | yes      |                  | Client ID of the provider                               |
| `OIDC_CLIENT_SECRET` | yes   |                  | Client secret of the provider                           |
| `OIDC_REDIRECT_URL`  | yes   |                  | Public callback URL of this app, ending in `/auth/callback` |
| `OIDC_ALLOWED_GROUPS` | yes  |                  | Comma-separated authentik groups whose members may log in |

The token's user needs permission to view, add, change and delete users (and to reset passwords).

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
set -a; source .env; set +a      # copy .env.example to .env first
# for development, OIDC_REDIRECT_URL=http://localhost:5173/auth/callback
make dev-backend    # API on 127.0.0.1:8080
make dev-frontend   # Vite on http://localhost:5173, /api and /auth are proxied to the backend
make test           # go vet + go test -race
make lint           # golangci-lint (.golangci.yml) + oxlint
make vuln           # govulncheck
```

### Git hooks

Run `make hooks` once per clone. It enables `.githooks/pre-commit`, which runs
`golangci-lint` and `govulncheck` when Go files, `go.mod`/`go.sum` or `.golangci.yml`
are staged, and `oxlint` when files under `frontend/` are staged. You need
`golangci-lint` (v2) and `govulncheck` (`go install golang.org/x/vuln/cmd/govulncheck@latest`).
Skip the checks once with `git commit --no-verify`.

## Production build

```sh
make build                         # frontend/dist + bin/authentik-manager
STATIC_DIR=frontend/dist ./bin/authentik-manager
```

## Security

- Every `/api/` route requires a login. The login uses authentik via OIDC: authorization code flow with PKCE, plus state and nonce checks. Only members of `OIDC_ALLOWED_GROUPS` get in.
- The browser only holds an opaque session cookie (`HttpOnly`, `SameSite=Lax`, and `Secure` with a `__Host-` prefix when served over https). ID and access tokens never reach the browser.
- Sessions live in memory for 8 hours. A restart logs everyone out, and you must run a single instance.
- Cross-origin state-changing requests are rejected (Go's `http.CrossOriginProtection`).
- Changes to users go to authentik with `AUTHENTIK_TOKEN`, not as the logged-in user. The app logs each change with the operator's username (`actor`).
- When serving over plain http on something other than localhost, put TLS in front of the app (reverse proxy).

## API

| Method | Path                       | Body                                                     |
| ------ | -------------------------- | -------------------------------------------------------- |
| GET    | `/api/users`               | query: `search`, `page`, `page_size` (≤100), `ordering`, `type` |
| POST   | `/api/users`               | `{username, name, email?, is_active?, path?, type?}`     |
| GET    | `/api/users/{id}`          |                                                          |
| PATCH  | `/api/users/{id}`          | any subset of the create fields                          |
| DELETE | `/api/users/{id}`          |                                                          |
| POST   | `/api/users/{id}/password` | `{password}`                                             |
| GET    | `/healthz`                 | no login required                                        |
| GET    | `/auth/login`              | starts the OIDC login                                     |
| GET    | `/auth/callback`           | OIDC redirect target                                      |
| GET    | `/auth/me`                 | the logged-in user, or 401                                |
| POST   | `/auth/logout`             | ends the session; returns `{logout_url}` for authentik    |

All `/api/` routes return 401 without a session. Errors are returned as `{"error": "...", "fields": {"field": ["message"]}}`.
