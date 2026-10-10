import CloseIcon from '@mui/icons-material/Close'
import Dialog from '@mui/material/Dialog'
import DialogTitle from '@mui/material/DialogTitle'
import IconButton from '@mui/material/IconButton'
import { useId, type ReactNode } from 'react'

interface ModalProps {
  title: string
  onClose: () => void
  /** DialogContent and DialogActions, optionally wrapped in a form. */
  children: ReactNode
  /** Use a wider dialog, e.g. for tables. */
  wide?: boolean
}

/** Dialog with a title bar and close button. */
export function Modal({ title, onClose, children, wide }: ModalProps) {
  const titleId = useId()
  return (
    <Dialog
      open
      onClose={onClose}
      fullWidth
      maxWidth={wide ? 'md' : 'xs'}
      aria-labelledby={titleId}
    >
      <DialogTitle id={titleId} sx={{ pr: 6 }}>
        {title}
      </DialogTitle>
      <IconButton
        onClick={onClose}
        aria-label="Close"
        sx={{ position: 'absolute', right: 8, top: 8 }}
      >
        <CloseIcon />
      </IconButton>
      {children}
    </Dialog>
  )
}
