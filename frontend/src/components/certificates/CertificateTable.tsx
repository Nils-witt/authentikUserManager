import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import LinearProgress from '@mui/material/LinearProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Tooltip from '@mui/material/Tooltip'
import type { Certificate, KeySource, OwnCertificate } from '../../api'

const KEY_SOURCE_LABELS: Record<KeySource, string> = {
  generated: 'Generated',
  csr: 'Own (CSR)',
  imported: 'Imported',
}

/**
 * The common name in a subject distinguished name as Go formats it (RFC 2253, e.g.
 * "CN=ann,O=Example"), unescaped; empty without one.
 */
function commonName(subject: string): string {
  let attribute = ''
  let value = ''
  let inValue = false
  for (let i = 0; i < subject.length; i++) {
    const ch = subject[i]
    if (ch === '\\' && i + 1 < subject.length) {
      value += subject[++i]
    } else if (!inValue && ch === '=') {
      attribute = value.trim()
      value = ''
      inValue = true
    } else if (ch === ',' || ch === '+') {
      if (attribute.toUpperCase() === 'CN') return value
      value = ''
      inValue = false
    } else {
      value += ch
    }
  }
  return inValue && attribute.toUpperCase() === 'CN' ? value : ''
}

/** Whether a certificate can still be used: neither revoked nor expired. */
const isActive = (c: Certificate) => !c.revoked_at && new Date(c.not_after) > new Date()

function Status({ certificate: c }: { certificate: Certificate }) {
  if (c.revoked_at) {
    return (
      <Tooltip title={`Revoked by ${c.revoked_by} on ${new Date(c.revoked_at).toLocaleString()}`}>
        <Chip size="small" color="error" label="Revoked" />
      </Tooltip>
    )
  }
  if (!isActive(c)) return <Chip size="small" label="Expired" />
  return <Chip size="small" color="success" label="Active" />
}

interface CertificateTableProps {
  /** The certificates, or null while loading. */
  certificates: (Certificate | OwnCertificate)[] | null
  /** Serial of the certificate an action runs for, so its buttons show progress. */
  busy: string | null
  loadFailed: boolean
  /** Show whose certificate each one is, for lists of several users. */
  showUser?: boolean
  /** Show the common name of each certificate's subject. */
  showCommonName?: boolean
  /** Revokes an active certificate; without it, there are no revoke buttons. */
  onRevoke?: (c: Certificate) => void
  /** Downloads the generated key; only for the user's own certificates. */
  onDownload?: (c: OwnCertificate) => void
  /** Downloads a stored certificate itself, without its key. */
  onDownloadCertificate?: (c: Certificate) => void
  /** Assigns an unassigned imported certificate to the account its common name names. */
  onAssign?: (c: Certificate) => void
}

/** Table of issued certificates with their state, and revoke and download buttons. */
export function CertificateTable({
  certificates,
  busy,
  loadFailed,
  showUser = false,
  showCommonName = false,
  onRevoke,
  onDownload,
  onDownloadCertificate,
  onAssign,
}: CertificateTableProps) {
  const hasActions =
    onRevoke !== undefined ||
    onDownload !== undefined ||
    onDownloadCertificate !== undefined ||
    onAssign !== undefined
  const columns = 5 + Number(showUser) + Number(showCommonName) + Number(hasActions)
  return (
    <TableContainer component={Paper} variant="outlined" aria-busy={certificates === null}>
      <Box sx={{ height: 4 }}>{certificates === null && !loadFailed && <LinearProgress />}</Box>
      <Table size="small">
        <TableHead>
          <TableRow>
            {showUser && <TableCell>User</TableCell>}
            {showCommonName && <TableCell>Common name</TableCell>}
            <TableCell>Serial</TableCell>
            <TableCell>Issued</TableCell>
            <TableCell>Expires</TableCell>
            <TableCell>Key</TableCell>
            <TableCell>Status</TableCell>
            {hasActions && <TableCell aria-label="Actions" />}
          </TableRow>
        </TableHead>
        <TableBody>
          {certificates?.map((c) => (
            <TableRow key={c.serial} hover>
              {showUser &&
                (c.username ? (
                  <TableCell title={`User ID ${c.user_pk}`}>{c.username}</TableCell>
                ) : (
                  <TableCell sx={{ color: 'text.secondary', fontStyle: 'italic' }}>
                    Unassigned
                  </TableCell>
                ))}
              {showCommonName && <TableCell title={c.subject}>{commonName(c.subject)}</TableCell>}
              <TableCell
                sx={{
                  fontFamily: 'monospace',
                  maxWidth: 160,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
                title={c.serial}
              >
                {c.serial}
              </TableCell>
              <TableCell sx={{ whiteSpace: 'nowrap' }}>
                {new Date(c.issued_at).toLocaleString()}
              </TableCell>
              <TableCell sx={{ whiteSpace: 'nowrap' }}>
                {new Date(c.not_after).toLocaleDateString()}
              </TableCell>
              <TableCell>{KEY_SOURCE_LABELS[c.key_source]}</TableCell>
              <TableCell>
                <Status certificate={c} />
              </TableCell>
              {hasActions && (
                <TableCell align="right">
                  <Stack direction="row" spacing={1} sx={{ justifyContent: 'flex-end' }}>
                    {onDownload && 'downloadable' in c && c.downloadable && (
                      <Button
                        size="small"
                        variant="contained"
                        loading={busy === c.serial}
                        disabled={busy !== null && busy !== c.serial}
                        onClick={() => onDownload(c)}
                      >
                        Download key
                      </Button>
                    )}
                    {onDownloadCertificate && c.stored && (
                      <Button
                        size="small"
                        loading={busy === c.serial}
                        disabled={busy !== null && busy !== c.serial}
                        onClick={() => onDownloadCertificate(c)}
                      >
                        Download
                      </Button>
                    )}
                    {onAssign && !c.username && isActive(c) && (
                      <Button
                        size="small"
                        loading={busy === c.serial}
                        disabled={busy !== null && busy !== c.serial}
                        onClick={() => onAssign(c)}
                      >
                        Assign
                      </Button>
                    )}
                    {onRevoke && isActive(c) && (
                      <Button
                        size="small"
                        color="error"
                        disabled={busy !== null}
                        onClick={() => onRevoke(c)}
                      >
                        Revoke
                      </Button>
                    )}
                  </Stack>
                </TableCell>
              )}
            </TableRow>
          ))}
          {certificates?.length === 0 && (
            <TableRow>
              <TableCell colSpan={columns} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                No certificates.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
