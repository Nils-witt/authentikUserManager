import DeleteIcon from '@mui/icons-material/Delete'
import EditIcon from '@mui/icons-material/Edit'
import Alert from '@mui/material/Alert'
import Autocomplete from '@mui/material/Autocomplete'
import Button from '@mui/material/Button'
import Checkbox from '@mui/material/Checkbox'
import Chip from '@mui/material/Chip'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import FormControlLabel from '@mui/material/FormControlLabel'
import IconButton from '@mui/material/IconButton'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import TextField from '@mui/material/TextField'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { useEffect, useState, type FormEvent } from 'react'
import * as api from '../api'
import { WILDCARD, type AccessRule } from '../api'
import { useConfirm } from './ConfirmDialog'
import { Modal } from './Modal'

const errorMessage = (err: unknown) => (err instanceof Error ? err.message : String(err))

/** Lets access administrators view and edit which groups may manage which users. */
export function AccessRules({ onClose }: { onClose: () => void }) {
  const [rules, setRules] = useState<AccessRule[] | null>(null)
  const [groups, setGroups] = useState<string[]>([])
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

  // Group names are only suggestions, so a failure here is not shown.
  useEffect(() => {
    api
      .listGroups()
      .then(setGroups)
      .catch(() => setGroups([]))
  }, [])

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
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Operator group</TableCell>
                  <TableCell>May manage members of</TableCell>
                  <TableCell aria-label="Actions" />
                </TableRow>
              </TableHead>
              <TableBody>
                {rules?.map((rule) => (
                  <TableRow key={rule.operator_group}>
                    <TableCell>{rule.operator_group}</TableCell>
                    <TableCell sx={{ whiteSpace: 'normal' }}>
                      <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
                        {rule.target_groups.map((t) => (
                          <Chip key={t} size="small" label={t === WILDCARD ? 'all users' : t} />
                        ))}
                      </Stack>
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Edit">
                        <IconButton size="small" onClick={() => setEditing(rule)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Remove">
                        <IconButton size="small" color="error" onClick={() => void remove(rule)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
                {rules?.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={3} align="center" sx={{ color: 'text.secondary', py: 3 }}>
                      No rules yet. Only access administrators can manage users.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
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

interface RuleFormProps {
  rule: AccessRule
  /** Known authentik group names, offered as suggestions. */
  groups: string[]
  onCancel: () => void
  onSaved: () => void
}

function RuleForm({ rule, groups, onCancel, onSaved }: RuleFormProps) {
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
