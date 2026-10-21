import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type {
  Certificate,
  IssueCertificateInput,
  IssuedCertificate,
  OwnCertificate,
} from '../../api'
import { saveFile } from '../../download'
import { errorMessage } from '../../errors'
import { useConfirm } from '../../hooks/useConfirm'
import { CertificateTable } from './CertificateTable'
import { IssueCertificateForm } from './IssueCertificateForm'

/** The calls managing the certificates of one account. */
interface CertificateCalls {
  list: () => Promise<OwnCertificate[]>
  issue: (input: IssueCertificateInput) => Promise<IssuedCertificate>
  revoke: (c: Certificate) => Promise<Certificate>
}

const ownCalls: CertificateCalls = {
  list: api.listMyCertificates,
  issue: api.issueCertificate,
  revoke: (c) => api.revokeCertificate(c.user_pk, c.serial),
}

function serviceAccountCalls(id: number): CertificateCalls {
  return {
    list: () => api.listServiceAccountCertificates(id),
    issue: (input) => api.issueServiceAccountCertificate(id, input),
    revoke: (c) => api.revokeServiceAccountCertificate(id, c.serial),
  }
}

interface CertificateManagerProps {
  /** Username of the account the certificates are issued to; it names the saved files. */
  username: string
  /** The service account whose certificates are managed; the signed-in user's own when undefined. */
  serviceAccountId?: number
}

/**
 * Issues certificates for an account, downloads a generated key once and revokes them: for the
 * signed-in user's own account, or for a service account the operator may change.
 */
export function CertificateManager({ username, serviceAccountId }: CertificateManagerProps) {
  // The certificates, or null while loading.
  const [certificates, setCertificates] = useState<OwnCertificate[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  // The last certificate issued for a CSR, which can be saved again until the page is left.
  const [signed, setSigned] = useState<IssuedCertificate | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  // Bumped after every change, to reload the certificates.
  const [version, setVersion] = useState(0)
  const [confirm, confirmDialog] = useConfirm()
  const calls = serviceAccountId === undefined ? ownCalls : serviceAccountCalls(serviceAccountId)
  const isOwn = serviceAccountId === undefined

  useEffect(() => {
    let cancelled = false
    const list =
      serviceAccountId === undefined
        ? ownCalls.list()
        : serviceAccountCalls(serviceAccountId).list()
    list
      .then((certs) => {
        if (!cancelled) setCertificates(certs)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [serviceAccountId, version])

  async function download(serial: string) {
    setBusy(serial)
    setError(null)
    try {
      const blob = await api.downloadCertificateKey(serial)
      const ext = blob.type === 'application/x-pkcs12' ? 'p12' : 'pem'
      saveFile(blob, `${username}.${ext}`)
      setNotice('Key downloaded. Keep the file safe: it cannot be downloaded again.')
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
      setVersion((v) => v + 1)
    }
  }

  function saveSigned(issued: IssuedCertificate) {
    saveFile(
      (issued.certificate_pem ?? '') + (issued.chain_pem ?? ''),
      `${username}.crt`,
      'application/x-pem-file',
    )
  }

  function issued(result: IssuedCertificate) {
    setNotice(null)
    setVersion((v) => v + 1)
    if (result.download_url) {
      setSigned(null)
      void download(result.certificate.serial)
      return
    }
    setSigned(result)
    saveSigned(result)
    setNotice('Certificate issued.')
  }

  async function revoke(c: Certificate) {
    const ok = await confirm({
      title: isOwn ? 'Revoke this certificate?' : `Revoke this certificate of ${username}?`,
      message: 'It stops working wherever the CRL is checked. This cannot be undone.',
      confirmLabel: 'Revoke',
    })
    if (!ok) return
    setBusy(c.serial)
    setError(null)
    try {
      await calls.revoke(c)
      setNotice('Certificate revoked.')
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
      setVersion((v) => v + 1)
    }
  }

  return (
    <Stack spacing={2}>
      {error && <Alert severity="error">{error}</Alert>}
      {notice && <Alert severity="success">{notice}</Alert>}
      {signed && (
        <Alert
          severity="info"
          action={
            <Button color="inherit" size="small" onClick={() => saveSigned(signed)}>
              Save again
            </Button>
          }
        >
          {isOwn ? 'Your certificate' : 'The certificate'} and the CA chain were saved as {username}
          .crt.
        </Alert>
      )}
      <IssueCertificateForm
        owner={isOwn ? undefined : username}
        issue={calls.issue}
        onIssued={issued}
      />
      <CertificateTable
        certificates={certificates}
        busy={busy}
        loadFailed={error !== null}
        // Own certificates may carry a chosen prefix, so their common names differ.
        showCommonName={isOwn}
        onRevoke={(c) => void revoke(c)}
        onDownload={(c) => void download(c.serial)}
      />
      {confirmDialog}
    </Stack>
  )
}
