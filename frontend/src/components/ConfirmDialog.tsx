import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import { useId, useState, type ReactNode } from 'react'

interface ConfirmOptions {
  title: string
  message: ReactNode
  /** Label of the confirm button, e.g. "Delete". */
  confirmLabel: string
  /** Color of the confirm button; destructive ("error") by default. */
  color?: 'error' | 'primary'
}

interface Pending extends ConfirmOptions {
  resolve: (ok: boolean) => void
}

/**
 * Promise-based replacement for window.confirm. Render the returned element
 * somewhere in the component; `confirm` resolves to true when the user agrees.
 */
export function useConfirm(): [(options: ConfirmOptions) => Promise<boolean>, ReactNode] {
  const [pending, setPending] = useState<Pending | null>(null)
  const titleId = useId()

  const confirm = (options: ConfirmOptions) =>
    new Promise<boolean>((resolve) => setPending({ ...options, resolve }))

  const close = (ok: boolean) => {
    pending?.resolve(ok)
    setPending(null)
  }

  const dialog = (
    <Dialog
      open={pending !== null}
      onClose={() => close(false)}
      maxWidth="xs"
      fullWidth
      aria-labelledby={titleId}
    >
      <DialogTitle id={titleId}>{pending?.title}</DialogTitle>
      <DialogContent>
        <DialogContentText>{pending?.message}</DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => close(false)} autoFocus>
          Cancel
        </Button>
        <Button color={pending?.color ?? 'error'} variant="contained" onClick={() => close(true)}>
          {pending?.confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  )

  return [confirm, dialog]
}
