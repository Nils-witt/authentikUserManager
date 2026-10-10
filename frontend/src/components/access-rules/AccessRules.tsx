import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import * as api from '../../api'
import type { AccessRule } from '../../api'
import { errorMessage } from '../../errors'
import { useConfirm } from '../../hooks/useConfirm'
import { useGroupNames } from '../../hooks/useGroupNames'
import { Modal } from '../common/Modal'
import { RuleForm } from './RuleForm'
import { RulesTable } from './RulesTable'

/** Lets access administrators view and edit which groups may manage which users. */
export function AccessRules({ onClose }: { onClose: () => void }) {
  const [rules, setRules] = useState<AccessRule[] | null>(null)
  const groups = useGroupNames()
  const [error, setError] = useState<string | null>(null)
  // The rule being edited; an empty operator group means a new rule.
  const [editing, setEditing] = useState<AccessRule | null>(null)
  const [version, setVersion] = useState(0)
  const [confirm, confirmDialog] = useConfirm()

  useEffect(() => {
    let cancelled = false
    api
      .listRules()
      .then((list) => {
        if (!cancelled) setRules(list)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [version])

  async function remove(rule: AccessRule) {
    const ok = await confirm({
      title: `Remove the rule for ${rule.operator_group}?`,
      message: 'Members of this group lose access to the users it grants.',
      confirmLabel: 'Remove',
    })
    if (!ok) return
    try {
      await api.deleteRule(rule.operator_group)
      setVersion((v) => v + 1)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  if (editing) {
    return (
      <Modal title="Access rules" onClose={onClose} wide>
        <RuleForm
          rule={editing}
          groups={groups}
          onCancel={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            setVersion((v) => v + 1)
          }}
        />
      </Modal>
    )
  }

  return (
    <Modal title="Access rules" onClose={onClose} wide>
      <DialogContent sx={{ pt: 0 }}>
        <Stack spacing={2}>
          {error && <Alert severity="error">{error}</Alert>}
          <Typography variant="body2" color="text.secondary">
            Members of an operator group may manage users who are members of one of its target
            groups. Access administrators always have full access.
          </Typography>
          <RulesTable rules={rules} onEdit={setEditing} onRemove={(rule) => void remove(rule)} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button
          variant="contained"
          onClick={() => setEditing({ operator_group: '', target_groups: [] })}
        >
          Add rule
        </Button>
      </DialogActions>
      {confirmDialog}
    </Modal>
  )
}
