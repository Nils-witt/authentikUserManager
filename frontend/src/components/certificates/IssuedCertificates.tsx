import FileUploadIcon from '@mui/icons-material/FileUpload'
import SearchIcon from '@mui/icons-material/Search'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Container from '@mui/material/Container'
import InputAdornment from '@mui/material/InputAdornment'
import MenuItem from '@mui/material/MenuItem'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { Certificate, CertificateStatus, Page } from '../../api'
import { saveFile } from '../../download'
import { errorMessage } from '../../errors'
import { useConfirm } from '../../hooks/useConfirm'
import { useDebounced } from '../../hooks/useDebounced'
import { ListPagination } from '../common/ListPagination'
import { NoticeSnackbar } from '../common/NoticeSnackbar'
import { CertificateTable } from './CertificateTable'
import { ImportCertificatesDialog } from './ImportCertificatesDialog'

const PAGE_SIZE = 20

const STATUS_LABELS: Record<CertificateStatus, string> = {
  active: 'Active',
  revoked: 'Revoked',
  expired: 'Expired',
}

const STATUSES = Object.keys(STATUS_LABELS) as CertificateStatus[]

/**
 * Lets access administrators review, download and revoke the certificates
 * issued to all users, including users who were deleted since, newest first,
 * and import certificates the CA signed elsewhere.
 */
export function IssuedCertificates() {
  const [search, setSearch] = useState('')
  const query = useDebounced(search)
  const [status, setStatus] = useState<CertificateStatus | ''>('')
  const [page, setPage] = useState(1)
  // The certificates loaded for the request in `key`.
  const [list, setList] = useState<{ key: string; data: Page<Certificate> } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  // Serial of the certificate an action runs for.
  const [busy, setBusy] = useState<string | null>(null)
  // Bumped after every revocation and import, to reload the list.
  const [version, setVersion] = useState(0)
  const [importing, setImporting] = useState(false)
  const [confirm, confirmDialog] = useConfirm()
  const requestKey = `${query}|${status}|${page}|${version}`
  const current = list?.key === requestKey ? list.data : null

  useEffect(() => {
    let cancelled = false
    api
      .listCertificates({ search: query, status: status || null, page, pageSize: PAGE_SIZE })
      .then((data) => {
        if (cancelled) return
        setList({ key: requestKey, data })
        setError(null)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [query, status, page, requestKey])

  async function download(c: Certificate) {
    setBusy(c.serial)
    setError(null)
    try {
      const pem = await api.downloadCertificate(c.serial)
      saveFile(
        pem,
        c.username ? `${c.username}-${c.serial}.crt` : `${c.serial}.crt`,
        'application/x-pem-file',
      )
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  async function assign(c: Certificate) {
    setBusy(c.serial)
    setError(null)
    try {
      const assigned = await api.assignCertificate(c.serial)
      setNotice(`Certificate assigned to ${assigned.username}.`)
      setVersion((v) => v + 1)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  async function revoke(c: Certificate) {
    const ok = await confirm({
      title: c.username
        ? `Revoke this certificate of ${c.username}?`
        : 'Revoke this unassigned certificate?',
      message: 'It stops working wherever the CRL is checked. This cannot be undone.',
      confirmLabel: 'Revoke',
    })
    if (!ok) return
    setBusy(c.serial)
    setError(null)
    try {
      await api.revokeAnyCertificate(c.serial)
      setNotice(c.username ? `Certificate of ${c.username} revoked.` : 'Certificate revoked.')
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
      setVersion((v) => v + 1)
    }
  }

  return (
    <Container component="main" maxWidth="xl" sx={{ py: 3 }}>
      <Stack spacing={2}>
        <Stack
          direction="row"
          spacing={2}
          sx={{ alignItems: 'center', justifyContent: 'space-between' }}
        >
          <Typography variant="h5" component="h2">
            Issued certificates
          </Typography>
          <Button startIcon={<FileUploadIcon />} onClick={() => setImporting(true)}>
            Import
          </Button>
        </Stack>
        <Typography variant="body2" color="text.secondary">
          Every client certificate issued by this application or imported, including those of
          deleted users and imported ones assigned to no user. An unassigned certificate can be
          assigned once the active account named by its common name exists. Downloads contain the
          certificate only, never its private key; certificates issued before downloads were added
          cannot be downloaded.
        </Typography>
        {error && <Alert severity="error">{error}</Alert>}
        <Stack direction="row" spacing={1.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
          <TextField
            type="search"
            size="small"
            placeholder="Username or serial…"
            aria-label="Search by username or serial number"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
            sx={{ flex: '1 1 220px', maxWidth: 400 }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon fontSize="small" />
                  </InputAdornment>
                ),
              },
            }}
          />
          <TextField
            select
            size="small"
            label="Status"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as CertificateStatus | '')
              setPage(1)
            }}
            sx={{ minWidth: 160 }}
          >
            <MenuItem value="">All</MenuItem>
            {STATUSES.map((s) => (
              <MenuItem key={s} value={s}>
                {STATUS_LABELS[s]}
              </MenuItem>
            ))}
          </TextField>
        </Stack>
        <CertificateTable
          certificates={current?.results ?? null}
          busy={busy}
          loadFailed={error !== null}
          showUser
          showCommonName
          onRevoke={(c) => void revoke(c)}
          onDownloadCertificate={(c) => void download(c)}
          onAssign={(c) => void assign(c)}
        />
        <ListPagination
          pagination={list?.data.pagination}
          page={page}
          onChange={setPage}
          noun="certificates"
        />
      </Stack>
      <NoticeSnackbar notice={notice} onClose={() => setNotice(null)} />
      {importing && (
        <ImportCertificatesDialog
          onClose={() => setImporting(false)}
          onImported={(count) => {
            setNotice(count === 1 ? '1 certificate imported.' : `${count} certificates imported.`)
            setPage(1)
            setVersion((v) => v + 1)
          }}
        />
      )}
      {confirmDialog}
    </Container>
  )
}
