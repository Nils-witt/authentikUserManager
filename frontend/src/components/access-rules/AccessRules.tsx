import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Container from '@mui/material/Container'
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

/**
 * Lets access administrators view and edit which groups may manage which users.
 * onChange is called after every change, since it may change the operator's own access.
 */
export function AccessRules({ onChange }: { onChange: () => void }) {
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
      onChange()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  return (
    <Container component="main" maxWidth="lg" sx={{ py: 3 }}>
      <Stack spacing={2}>
        <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
          <Typography variant="h5" component="h2">
            Access rules
          </Typography>
          <Box sx={{ flexGrow: 1 }} />
          <Button
            variant="contained"
            onClick={() => setEditing({ operator_group: '', target_groups: [] })}
          >
            Add rule
          </Button>
        </Stack>
        {error && <Alert severity="error">{error}</Alert>}
        <Typography variant="body2" color="text.secondary">
          Members of an operator group may manage users who are members of one of its target groups.
          Access administrators always have full access.
        </Typography>
        <RulesTable rules={rules} onEdit={setEditing} onRemove={(rule) => void remove(rule)} />
      </Stack>
      {editing && (
        <Modal
          title={
            editing.operator_group === '' ? 'Add rule' : `Edit rule for ${editing.operator_group}`
          }
          onClose={() => setEditing(null)}
          wide
        >
          <RuleForm
            rule={editing}
            groups={groups}
            onCancel={() => setEditing(null)}
            onSaved={() => {
              setEditing(null)
              setVersion((v) => v + 1)
              onChange()
            }}
          />
        </Modal>
      )}
      {confirmDialog}
    </Container>
  )
}
