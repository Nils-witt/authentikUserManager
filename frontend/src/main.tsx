import createCache from '@emotion/cache'
import { CacheProvider } from '@emotion/react'
import CssBaseline from '@mui/material/CssBaseline'
import { ThemeProvider } from '@mui/material/styles'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from 'react-router'
import { router } from './routes'
import { theme } from './theme'

// The server's Content-Security-Policy only allows <style> elements carrying
// its per-request nonce, so Emotion must tag the ones it injects.
const nonce = document.querySelector<HTMLMetaElement>('meta[property="csp-nonce"]')?.nonce
const emotionCache = createCache({ key: 'css', nonce })

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <CacheProvider value={emotionCache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <RouterProvider router={router} />
      </ThemeProvider>
    </CacheProvider>
  </StrictMode>,
)
