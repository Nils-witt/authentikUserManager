import SearchIcon from '@mui/icons-material/Search'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import InputAdornment from '@mui/material/InputAdornment'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import ToggleButton from '@mui/material/ToggleButton'
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup'
import type { StatusFilter } from '../../hooks/useUserFilters'

interface UserToolbarProps {
  search: string
  onSearchChange: (value: string) => void
  status: StatusFilter
  onStatusChange: (value: StatusFilter | null) => void
  /** Called to create a user; the button is hidden when undefined. */
  onCreate?: () => void
  /** What the listed accounts are called; defaults to "user". */
  noun?: string
}

/** Search box, status filter and the actions above the user table. */
export function UserToolbar({
  search,
  onSearchChange,
  status,
  onStatusChange,
  onCreate,
  noun = 'user',
}: UserToolbarProps) {
  return (
    <Stack
      direction="row"
      spacing={1.5}
      useFlexGap
      sx={{ mb: 2, flexWrap: 'wrap', alignItems: 'center' }}
    >
      <TextField
        type="search"
        size="small"
        placeholder={`Search ${noun}s…`}
        aria-label={`Search ${noun}s`}
        value={search}
        onChange={(e) => onSearchChange(e.target.value)}
        sx={{ flex: '1 1 280px', maxWidth: 400 }}
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
          },
        }}
      />
      <ToggleButtonGroup
        exclusive
        size="small"
        aria-label="Filter by status"
        value={status}
        onChange={(_, value: StatusFilter | null) => onStatusChange(value)}
      >
        <ToggleButton value="all">All</ToggleButton>
        <ToggleButton value="active">Active</ToggleButton>
        <ToggleButton value="inactive">Inactive</ToggleButton>
      </ToggleButtonGroup>
      <Box sx={{ flexGrow: 1 }} />
      {onCreate && (
        <Button variant="contained" onClick={onCreate}>
          New {noun}
        </Button>
      )}
    </Stack>
  )
}
