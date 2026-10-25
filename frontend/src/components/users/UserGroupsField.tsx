import StarIcon from '@mui/icons-material/Star'
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
  /** Name of the user's primary group; it is marked and cannot be removed. */
  primary?: string
  /** Shows the groups without letting them be changed. */
  disabled?: boolean
  /** Validation error shown on the field. */
  errorProps?: Pick<TextFieldProps, 'error' | 'helperText'>
}

/**
 * Edits a user's group memberships; groups outside the operator's scope and the primary group stay
 * as they are.
 */
export function UserGroupsField({
  value,
  onChange,
  groups,
  suggestions,
  primary,
  disabled = false,
  errorProps,
}: UserGroupsFieldProps) {
  const removable = (g: string) => g !== primary && (!groups || groups.includes(g))
  const fixed = value.filter((g) => !removable(g))

  return (
    <Autocomplete
      multiple
      disabled={disabled}
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
              title={g === primary ? 'Primary group' : undefined}
              icon={g === primary ? <StarIcon /> : undefined}
              {...itemProps}
              onDelete={removable(g) ? onDelete : undefined}
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
