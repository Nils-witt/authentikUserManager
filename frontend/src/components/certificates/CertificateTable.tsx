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
import type { Certificate, OwnCertificate } from '../../api'

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
  onRevoke: (c: Certificate) => void
  /** Downloads the generated key; only for the user's own certificates. */
  onDownload?: (c: OwnCertificate) => void
}

/** Table of issued certificates with their state, and revoke and download buttons. */
export function CertificateTable({
  certificates,
  busy,
  loadFailed,
  onRevoke,
  onDownload,
}: CertificateTableProps) {
  return (
    <TableContainer component={Paper} variant="outlined" aria-busy={certificates === null}>
      <Box sx={{ height: 4 }}>{certificates === null && !loadFailed && <LinearProgress />}</Box>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Serial</TableCell>
            <TableCell>Issued</TableCell>
            <TableCell>Expires</TableCell>
            <TableCell>Key</TableCell>
            <TableCell>Status</TableCell>
            <TableCell aria-label="Actions" />
          </TableRow>
        </TableHead>
        <TableBody>
          {certificates?.map((c) => (
            <TableRow key={c.serial} hover>
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
              <TableCell>{c.key_source === 'csr' ? 'Own (CSR)' : 'Generated'}</TableCell>
              <TableCell>
                <Status certificate={c} />
              </TableCell>
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
                  {isActive(c) && (
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
            </TableRow>
          ))}
          {certificates?.length === 0 && (
            <TableRow>
              <TableCell colSpan={6} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                No certificates.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
