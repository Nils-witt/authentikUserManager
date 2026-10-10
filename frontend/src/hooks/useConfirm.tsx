import { useState, type ReactNode } from 'react'
import { ConfirmDialog, type ConfirmOptions } from '../components/common/ConfirmDialog'

interface Pending extends ConfirmOptions {
  resolve: (ok: boolean) => void
}

/**
 * Promise-based replacement for window.confirm. Render the returned element
 * somewhere in the component; `confirm` resolves to true when the user agrees.
 */
export function useConfirm(): [(options: ConfirmOptions) => Promise<boolean>, ReactNode] {
  const [pending, setPending] = useState<Pending | null>(null)

  const confirm = (options: ConfirmOptions) =>
    new Promise<boolean>((resolve) => setPending({ ...options, resolve }))

  const close = (ok: boolean) => {
    pending?.resolve(ok)
    setPending(null)
  }

  const dialog = <ConfirmDialog options={pending} onClose={close} />
  return [confirm, dialog]
}
