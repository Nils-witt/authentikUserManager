import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import { useId, type ReactNode } from 'react'

export interface ConfirmOptions {
  title: string
  message: ReactNode
  /** Label of the confirm button, e.g. "Delete". */
  confirmLabel: string
  /** Color of the confirm button; destructive ("error") by default. */
  color?: 'error' | 'primary'
}

interface ConfirmDialogProps {
  /** The question to ask, or null while the dialog is closed. */
  options: ConfirmOptions | null
  onClose: (ok: boolean) => void
}

/** Asks the user to confirm or cancel an action. */
export function ConfirmDialog({ options, onClose }: ConfirmDialogProps) {
  const titleId = useId()
  return (
    <Dialog
      open={options !== null}
      onClose={() => onClose(false)}
      maxWidth="xs"
      fullWidth
      aria-labelledby={titleId}
    >
      <DialogTitle id={titleId}>{options?.title}</DialogTitle>
      <DialogContent>
        <DialogContentText>{options?.message}</DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => onClose(false)} autoFocus>
          Cancel
        </Button>
        <Button color={options?.color ?? 'error'} variant="contained" onClick={() => onClose(true)}>
          {options?.confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  )
}
