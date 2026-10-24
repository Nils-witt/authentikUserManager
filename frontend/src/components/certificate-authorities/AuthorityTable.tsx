import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import LinearProgress from '@mui/material/LinearProgress'
import Link from '@mui/material/Link'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import type { CertificateAuthority } from '../../api'

interface AuthorityTableProps {
  /** The CAs, or null while they load. */
  authorities: CertificateAuthority[] | null
  loadFailed: boolean
  /** ID of the CA an action runs for, so its buttons show progress. */
  busy: number | null
  onEdit: (a: CertificateAuthority) => void
  onMakeDefault: (a: CertificateAuthority) => void
}

/** Lists the certificate authorities with their state and the accounts they issue for. */
export function AuthorityTable({
  authorities,
  loadFailed,
  busy,
  onEdit,
  onMakeDefault,
}: AuthorityTableProps) {
  return (
    <TableContainer component={Paper} variant="outlined" aria-busy={authorities === null}>
      <Box sx={{ height: 4 }}>{authorities === null && !loadFailed && <LinearProgress />}</Box>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Name</TableCell>
            <TableCell>Subject</TableCell>
            <TableCell>Expires</TableCell>
            <TableCell>Issues for</TableCell>
            <TableCell>Published</TableCell>
            <TableCell aria-label="Actions" />
          </TableRow>
        </TableHead>
        <TableBody>
          {authorities?.map((a) => (
            <TableRow key={a.id} hover>
              <TableCell>
                <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
                  <span title={a.description}>{a.name}</span>
                  {a.default && <Chip size="small" color="primary" label="Default" />}
                  {a.disabled && <Chip size="small" label="Disabled" />}
                </Stack>
              </TableCell>
              <TableCell title={`Issuer: ${a.issuer}\nSHA-256: ${a.fingerprint_sha256}`}>
                {a.subject}
              </TableCell>
              <TableCell sx={{ whiteSpace: 'nowrap' }}>
                {new Date(a.not_after).toLocaleDateString()}
              </TableCell>
              <TableCell sx={{ whiteSpace: 'normal' }}>
                {a.allowed_groups.length === 0 ? (
                  <Chip size="small" label="all accounts" />
                ) : (
                  <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
                    {a.allowed_groups.map((g) => (
                      <Chip key={g} size="small" label={g} />
                    ))}
                  </Stack>
                )}
              </TableCell>
              <TableCell sx={{ whiteSpace: 'nowrap' }}>
                <Link href={`/pki/${a.name}/ca.pem`}>Chain</Link>
                {' · '}
                <Link href={`/pki/${a.name}/crl.pem`}>CRL</Link>
              </TableCell>
              <TableCell align="right">
                <Stack direction="row" spacing={1} sx={{ justifyContent: 'flex-end' }}>
                  {!a.default && !a.disabled && (
                    <Button
                      size="small"
                      loading={busy === a.id}
                      disabled={busy !== null && busy !== a.id}
                      onClick={() => onMakeDefault(a)}
                    >
                      Make default
                    </Button>
                  )}
                  <Button size="small" disabled={busy !== null} onClick={() => onEdit(a)}>
                    Edit
                  </Button>
                </Stack>
              </TableCell>
            </TableRow>
          ))}
          {authorities?.length === 0 && (
            <TableRow>
              <TableCell colSpan={6} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                No certificate authorities yet. Add one to issue certificates.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
