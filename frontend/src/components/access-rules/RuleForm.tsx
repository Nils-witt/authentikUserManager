import Alert from '@mui/material/Alert'
import Autocomplete from '@mui/material/Autocomplete'
import Button from '@mui/material/Button'
import Checkbox from '@mui/material/Checkbox'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import FormControlLabel from '@mui/material/FormControlLabel'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import { useState, type FormEvent } from 'react'
import * as api from '../../api'
import { WILDCARD, type AccessRule } from '../../api'
import { errorMessage } from '../../errors'

interface RuleFormProps {
  /** The rule to edit; an empty operator group means a new rule. */
  rule: AccessRule
  /** Known authentik group names, offered as suggestions. */
  groups: string[]
  onCancel: () => void
  onSaved: () => void
}

/** Creates or edits one access rule. */
export function RuleForm({ rule, groups, onCancel, onSaved }: RuleFormProps) {
  const isNew = rule.operator_group === ''
  const [operatorGroup, setOperatorGroup] = useState(rule.operator_group)
  const [all, setAll] = useState(rule.target_groups.includes(WILDCARD))
  const [targets, setTargets] = useState(rule.target_groups.filter((t) => t !== WILDCARD))
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const targetGroups = all ? [WILDCARD] : targets
    if (targetGroups.length === 0) {
      setError('Add at least one target group, or allow all users.')
      return
    }
    setSaving(true)
    setError(null)
    try {
      await api.putRule({ operator_group: operatorGroup.trim(), target_groups: targetGroups })
      onSaved()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <DialogContent sx={{ pt: 0 }}>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <Autocomplete
            freeSolo
            options={groups}
            disabled={!isNew}
            inputValue={operatorGroup}
            onInputChange={(_, value) => setOperatorGroup(value)}
            renderInput={(params) => <TextField {...params} label="Operator group" required />}
          />
          <FormControlLabel
            label="May manage all users, including administrators"
            control={<Checkbox checked={all} onChange={(e) => setAll(e.target.checked)} />}
          />
          {!all && (
            <Autocomplete
              multiple
              freeSolo
              options={groups.filter((g) => !targets.includes(g))}
              value={targets}
              onChange={(_, value) =>
                setTargets([...new Set(value.map((v) => v.trim()))].filter(Boolean))
              }
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="May manage members of"
                  placeholder="Group name, then Enter"
                />
              )}
            />
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel}>Cancel</Button>
        <Button type="submit" variant="contained" loading={saving}>
          Save
        </Button>
      </DialogActions>
    </form>
  )
}
