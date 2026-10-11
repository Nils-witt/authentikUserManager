import Alert from '@mui/material/Alert'
import Container from '@mui/material/Container'
import LinearProgress from '@mui/material/LinearProgress'
import type { ReactNode } from 'react'
import { Navigate } from 'react-router'
import { pagePaths } from '../../paths'
import { useAppContext } from '../../hooks/useAppContext'

/**
 * Renders a page once the operator's access has loaded and `allow`s it;
 * an operator who may not see the page is sent to the user list.
 */
export function AccessGate({ allow, children }: { allow: boolean; children: ReactNode }) {
  const { access, accessError } = useAppContext()
  if (access === null) {
    return (
      <Container component="main" maxWidth="lg" sx={{ py: 3 }}>
        {accessError ? <Alert severity="error">{accessError}</Alert> : <LinearProgress />}
      </Container>
    )
  }
  if (!allow) return <Navigate to={pagePaths.users} replace />
  return children
}
