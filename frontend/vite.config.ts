import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // The Go binary embeds the build from here (internal/web, //go:embed).
    outDir: '../internal/web/dist',
    emptyOutDir: true,
  },
  server: {
    // Forward API and login calls to the Go backend during development.
    // The Host header is kept, so session cookies are set for localhost:5173.
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/auth': 'http://127.0.0.1:8080',
    },
  },
})
