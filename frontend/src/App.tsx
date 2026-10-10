import Alert from '@mui/material/Alert'
import CircularProgress from '@mui/material/CircularProgress'
import Container from '@mui/material/Container'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from './api'
import type { Me } from './api'
import { UserAdmin } from './components/users/UserAdmin'
import { errorMessage } from './errors'

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
        setError(errorMessage(err))
      })
  }, [])

  if (error) {
    return (
      <Container component="main" sx={{ py: 3 }}>
        <Alert severity="error">{error}</Alert>
      </Container>
    )
  }
  if (!me) {
    return (
      <Stack component="main" spacing={2} sx={{ alignItems: 'center', py: 8 }}>
        <CircularProgress />
        <Typography color="text.secondary">Signing in…</Typography>
      </Stack>
    )
  }
  return <UserAdmin me={me} />
}
