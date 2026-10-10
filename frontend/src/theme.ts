import { createTheme } from '@mui/material/styles'

/** App theme; follows the system light/dark preference. */
export const theme = createTheme({
  cssVariables: true,
  colorSchemes: {
    light: { palette: { primary: { main: '#fd4b2d' } } },
    dark: { palette: { primary: { main: '#fd4b2d' } } },
  },
  shape: { borderRadius: 6 },
  components: {
    MuiButton: { defaultProps: { disableElevation: true } },
    MuiTableCell: { styleOverrides: { root: { whiteSpace: 'nowrap' } } },
  },
})
