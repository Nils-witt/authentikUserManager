import Autocomplete from '@mui/material/Autocomplete'
import Chip from '@mui/material/Chip'
import TextField, { type TextFieldProps } from '@mui/material/TextField'

interface UserGroupsFieldProps {
  /** Names of the groups the user is a member of. */
  value: string[]
  onChange: (groups: string[]) => void
  /** Groups the operator may add or remove; undefined means any group. */
  groups?: string[]
  /** Group names suggested when any group may be chosen. */
  suggestions?: string[]
  /** Validation error shown on the field. */
  errorProps?: Pick<TextFieldProps, 'error' | 'helperText'>
}

/** Edits a user's group memberships; groups outside the operator's scope stay as they are. */
export function UserGroupsField({
  value,
  onChange,
  groups,
  suggestions,
  errorProps,
}: UserGroupsFieldProps) {
  const editable = (g: string) => !groups || groups.includes(g)
  const fixed = value.filter((g) => !editable(g))

  return (
    <Autocomplete
      multiple
      freeSolo={!groups}
      disableClearable
      options={(groups ?? suggestions ?? []).filter((g) => !value.includes(g))}
      value={value}
      onChange={(_, next) =>
        onChange([...new Set([...fixed, ...next.map((v) => v.trim()).filter(Boolean)])])
      }
      renderValue={(selected, getItemProps) =>
        selected.map((g, index) => {
          const { key, onDelete, ...itemProps } = getItemProps({ index })
          return (
            <Chip
              key={key}
              size="small"
              label={g}
              {...itemProps}
              onDelete={editable(g) ? onDelete : undefined}
            />
          )
        })
      }
      renderInput={(params) => (
        <TextField
          {...params}
          label="Groups"
          placeholder={groups ? 'Add a group' : 'Group name, then Enter'}
          {...errorProps}
        />
      )}
    />
  )
}
