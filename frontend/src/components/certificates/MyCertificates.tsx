import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Container from '@mui/material/Container'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { Certificate, IssuedCertificate, OwnCertificate } from '../../api'
import { saveFile } from '../../download'
import { errorMessage } from '../../errors'
import { useConfirm } from '../../hooks/useConfirm'
import { CertificateTable } from './CertificateTable'
import { IssueCertificateForm } from './IssueCertificateForm'

/** The signed-in user's certificates: issuing, downloading the generated key once, and revoking. */
export function MyCertificates({ username }: { username: string }) {
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

  useEffect(() => {
    let cancelled = false
    api
      .listMyCertificates()
      .then((list) => {
        if (!cancelled) setCertificates(list)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [version])

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
      title: 'Revoke this certificate?',
      message: 'It stops working wherever the CRL is checked. This cannot be undone.',
      confirmLabel: 'Revoke',
    })
    if (!ok) return
    setBusy(c.serial)
    setError(null)
    try {
      await api.revokeCertificate(c.user_pk, c.serial)
      setNotice('Certificate revoked.')
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
      setVersion((v) => v + 1)
    }
  }

  return (
    <Container component="main" maxWidth="lg" sx={{ py: 3 }}>
      <Stack spacing={2}>
        <Typography variant="h5" component="h2">
          Certificates
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Client certificates for your account. The <Link href="/pki/ca.pem">CA certificate</Link>{' '}
          and the <Link href="/pki/crl">revocation list</Link> are public.
        </Typography>
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
            Your certificate and the CA chain were saved as {username}.crt.
          </Alert>
        )}
        <IssueCertificateForm onIssued={issued} />
        <CertificateTable
          certificates={certificates}
          busy={busy}
          loadFailed={error !== null}
          onRevoke={(c) => void revoke(c)}
          onDownload={(c) => void download(c.serial)}
        />
      </Stack>
      {confirmDialog}
    </Container>
  )
}
