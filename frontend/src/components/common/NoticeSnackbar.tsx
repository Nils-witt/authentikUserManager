import Alert from '@mui/material/Alert'
import Snackbar from '@mui/material/Snackbar'

interface NoticeSnackbarProps {
  /** Success message to show, or null to hide the snackbar. */
  notice: string | null
  onClose: () => void
}

/** Briefly shows the outcome of a successful action. */
export function NoticeSnackbar({ notice, onClose }: NoticeSnackbarProps) {
  return (
    <Snackbar
      open={notice !== null}
      autoHideDuration={6000}
      onClose={(_, reason) => {
        if (reason !== 'clickaway') onClose()
      }}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      <Alert severity="success" variant="filled" onClose={onClose}>
        {notice}
      </Alert>
    </Snackbar>
  )
}
