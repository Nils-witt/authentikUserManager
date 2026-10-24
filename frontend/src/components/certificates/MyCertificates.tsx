import Container from '@mui/material/Container'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { CertificateManager } from './CertificateManager'

/** The signed-in user's certificates: issuing, downloading the generated key once, and revoking. */
export function MyCertificates({ username }: { username: string }) {
  return (
    <Container component="main" maxWidth="lg" sx={{ py: 3 }}>
      <Stack spacing={2}>
        <Stack
          direction="row"
          spacing={2}
          sx={{ alignItems: 'center', justifyContent: 'space-between' }}
        >
          <Typography variant="h5" component="h2">
            Certificates
          </Typography>
        </Stack>
        <CertificateManager username={username} />
      </Stack>
    </Container>
  )
}
