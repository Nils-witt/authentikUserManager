import Container from '@mui/material/Container'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { CertificateManager } from './CertificateManager'

/** The signed-in user's certificates: issuing, downloading the generated key once, and revoking. */
export function MyCertificates({ username }: { username: string }) {
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
        <CertificateManager username={username} />
      </Stack>
    </Container>
  )
}
