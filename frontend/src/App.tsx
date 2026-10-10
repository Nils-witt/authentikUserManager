import { useEffect, useState } from 'react'
import * as api from './api'
import type { Me, User, UserList } from './api'
import { FolderTree } from './components/FolderTree'
import { PasswordForm } from './components/PasswordForm'
import { UserForm } from './components/UserForm'

const PAGE_SIZE = 20

type Dialog =
  | { kind: 'create' }
  | { kind: 'edit'; user: User }
  | { kind: 'password'; user: User }
  | null

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : '—'
}

/** Ensures the operator is signed in before showing the user admin. */
export default function App() {
  const [me, setMe] = useState<Me | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .me()
      .then(setMe)
      .catch((err: unknown) => {
        // A 401 has already triggered the redirect to the login.
        if (err instanceof api.ApiError && err.status === 401) return
        setError(err instanceof Error ? err.message : String(err))
      })
  }, [])

  if (error) {
    return (
      <main className="app">
        <p className="alert" role="alert">
          {error}
        </p>
      </main>
    )
  }
  if (!me) {
    return <main className="app loading">Signing in…</main>
  }
  return <UserAdmin me={me} />
}

async function signOut() {
  try {
    const { logout_url } = await api.logout()
    // End the authentik session too, so the next login asks for credentials again.
    window.location.assign(logout_url ?? '/auth/login')
  } catch {
    window.location.assign('/auth/login')
  }
}

function UserAdmin({ me }: { me: Me }) {
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  // Selected user folder (path), or null for all users.
  const [folder, setFolder] = useState<string | null>(null)
  const [paths, setPaths] = useState<string[]>([])
  const [data, setData] = useState<UserList | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dialog, setDialog] = useState<Dialog>(null)

  // Debounce the search box so we don't query authentik on every keystroke.
  useEffect(() => {
    const id = setTimeout(() => {
      setQuery(search.trim())
      setPage(1)
    }, 300)
    return () => clearTimeout(id)
  }, [search])

  // Bumped after every mutation to refetch the current page.
  const [version, setVersion] = useState(0)
  const requestKey = `${query}|${folder}|${page}|${version}`
  const [loadedKey, setLoadedKey] = useState<string | null>(null)
  const loading = loadedKey !== requestKey

  useEffect(() => {
    let cancelled = false
    api
      .listUsers({ search: query, page, pageSize: PAGE_SIZE, path: folder ?? undefined })
      .then((list) => {
        if (cancelled) return
        setData(list)
        setError(null)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setLoadedKey(requestKey)
      })
    return () => {
      cancelled = true
    }
  }, [query, folder, page, requestKey])

  // Reload the folders after mutations too, since a user's path may have changed.
  useEffect(() => {
    let cancelled = false
    api
      .listUserPaths()
      .then((list) => {
        if (!cancelled) setPaths(list)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      })
    return () => {
      cancelled = true
    }
  }, [version])

  function selectFolder(path: string | null) {
    setFolder(path)
    setPage(1)
  }

  const done = (message: string) => {
    setDialog(null)
    setNotice(message)
    setVersion((v) => v + 1)
  }

  async function toggleActive(user: User) {
    try {
      await api.updateUser(user.pk, { is_active: !user.is_active })
      done(`${user.username} ${user.is_active ? 'deactivated' : 'activated'}.`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function remove(user: User) {
    if (!window.confirm(`Delete user "${user.username}"? This cannot be undone.`)) return
    try {
      await api.deleteUser(user.pk)
      done(`${user.username} deleted.`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const pagination = data?.pagination

  return (
    <main className="app">
      <header className="toolbar">
        <h1>Authentik users</h1>
        <input
          type="search"
          placeholder="Search users…"
          aria-label="Search users"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <button type="button" className="primary" onClick={() => setDialog({ kind: 'create' })}>
          New user
        </button>
        <span className="me" title={me.email}>
          {me.name || me.username}
        </span>
        <button type="button" onClick={() => void signOut()}>
          Sign out
        </button>
      </header>

      {error && (
        <p className="alert" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="notice" role="status" onClick={() => setNotice(null)}>
          {notice}
        </p>
      )}

      <div className="layout">
        <FolderTree paths={paths} selected={folder} onSelect={selectFolder} />
        <section className="content">
          <div className="table-wrap" aria-busy={loading}>
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Last login</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {data?.results.map((user) => (
                  <tr key={user.pk} className={user.is_active ? undefined : 'inactive'}>
                    <td>
                      <span className="user-cell">
                        {user.avatar && <img src={user.avatar} alt="" className="avatar" />}
                        {user.username}
                        {user.is_superuser && <span className="badge">admin</span>}
                      </span>
                    </td>
                    <td>{user.name}</td>
                    <td>{user.email || '—'}</td>
                    <td>{user.type.replaceAll('_', ' ')}</td>
                    <td>{user.is_active ? 'active' : 'inactive'}</td>
                    <td>{formatDate(user.last_login)}</td>
                    <td className="actions">
                      <button type="button" onClick={() => setDialog({ kind: 'edit', user })}>
                        Edit
                      </button>
                      <button type="button" onClick={() => setDialog({ kind: 'password', user })}>
                        Password
                      </button>
                      <button type="button" onClick={() => void toggleActive(user)}>
                        {user.is_active ? 'Deactivate' : 'Activate'}
                      </button>
                      <button type="button" className="danger" onClick={() => void remove(user)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
                {data && data.results.length === 0 && (
                  <tr>
                    <td colSpan={7} className="empty">
                      No users found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {pagination && pagination.total_pages > 1 && (
            <nav className="pager" aria-label="Pagination">
              <button type="button" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                Previous
              </button>
              <span>
                Page {pagination.current} of {pagination.total_pages} ({pagination.count} users)
              </span>
              <button
                type="button"
                disabled={page >= pagination.total_pages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </button>
            </nav>
          )}
        </section>
      </div>

      {dialog?.kind === 'create' && (
        <UserForm
          defaultPath={folder ?? undefined}
          onClose={() => setDialog(null)}
          onSubmit={async (input) => {
            const user = await api.createUser(input)
            done(`${user.username} created. Set a password so they can log in.`)
          }}
        />
      )}
      {dialog?.kind === 'edit' && (
        <UserForm
          user={dialog.user}
          onClose={() => setDialog(null)}
          onSubmit={async (input) => {
            await api.updateUser(dialog.user.pk, input)
            done(`${input.username} saved.`)
          }}
        />
      )}
      {dialog?.kind === 'password' && (
        <PasswordForm
          user={dialog.user}
          onClose={() => setDialog(null)}
          onSubmit={async (password) => {
            await api.setPassword(dialog.user.pk, password)
            done(`Password for ${dialog.user.username} updated.`)
          }}
        />
      )}
    </main>
  )
}
