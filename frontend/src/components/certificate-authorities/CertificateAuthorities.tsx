import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Container from '@mui/material/Container'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { CertificateAuthority } from '../../api'
import { errorMessage } from '../../errors'
import { useGroupNames } from '../../hooks/useGroupNames'
import { Modal } from '../common/Modal'
import { AuthorityForm } from './AuthorityForm'
import { AuthorityTable } from './AuthorityTable'

/**
 * Lists the certificate authorities. When canManage is set, it lets access administrators add
 * them, choose which accounts each one issues certificates for and which one is the default, and
 * disable them. CAs are never deleted, so the CRLs of the certificates they issued stay published.
 * onChange is called after every change, since it may change the suffixes the app shows.
 */
export function CertificateAuthorities({
  canManage,
  onChange,
}: {
  canManage: boolean
  onChange: () => void
}) {
  const [authorities, setAuthorities] = useState<CertificateAuthority[] | null>(null)
  const groups = useGroupNames(canManage)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  // The CA being edited, 'new' while adding one, or null.
  const [editing, setEditing] = useState<CertificateAuthority | 'new' | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  // Bumped after every change, to reload the CAs.
  const [version, setVersion] = useState(0)

  useEffect(() => {
    let cancelled = false
    api
      .listAuthorities()
      .then((list) => {
        if (!cancelled) setAuthorities(list)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [version])

  async function makeDefault(a: CertificateAuthority) {
    setBusy(a.id)
    setError(null)
    try {
      await api.setDefaultAuthority(a.id)
      setNotice(`${a.name} now signs certificates when no CA is chosen.`)
      setVersion((v) => v + 1)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  function saved(a: CertificateAuthority) {
    setNotice(editing === 'new' ? `${a.name} was added.` : `${a.name} was saved.`)
    setEditing(null)
    setVersion((v) => v + 1)
    onChange()
  }

  return (
    <Container component="main" maxWidth="lg" sx={{ py: 3 }}>
      <Stack spacing={2}>
        <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
          <Typography variant="h5" component="h2">
            Certificate authorities
          </Typography>
          <Box sx={{ flexGrow: 1 }} />
          {canManage && (
            <Button variant="contained" onClick={() => setEditing('new')}>
              Add CA
            </Button>
          )}
        </Stack>
        {error && <Alert severity="error">{error}</Alert>}
        {notice && <Alert severity="success">{notice}</Alert>}
        <Typography variant="body2" color="text.secondary">
          Users and operators choose among the enabled CAs that issue certificates for the account;
          the default one signs when they choose none. Each CA publishes its CRL and chain at
          /pki/&lt;id&gt;/crl and /pki/&lt;id&gt;/ca.pem, by its UUID.
        </Typography>
        <AuthorityTable
          authorities={authorities}
          loadFailed={error !== null}
          busy={busy}
          onEdit={canManage ? setEditing : undefined}
          onMakeDefault={canManage ? (a) => void makeDefault(a) : undefined}
        />
      </Stack>
      {editing && (
        <Modal
          title={editing === 'new' ? 'Add certificate authority' : `Edit ${editing.name}`}
          onClose={() => setEditing(null)}
          wide
        >
          <AuthorityForm
            authority={editing === 'new' ? undefined : editing}
            groups={groups}
            onCancel={() => setEditing(null)}
            onSaved={saved}
          />
        </Modal>
      )}
    </Container>
  )
}
