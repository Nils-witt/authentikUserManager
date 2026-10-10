import Pagination from '@mui/material/Pagination'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import type { Pagination as PageInfo } from '../../api'

interface UserPaginationProps {
  /** Paging info of the loaded list, or undefined before the first load. */
  pagination: PageInfo | undefined
  page: number
  onChange: (page: number) => void
}

/** Page switcher and user count below the table; hidden for a single page. */
export function UserPagination({ pagination, page, onChange }: UserPaginationProps) {
  if (!pagination || pagination.total_pages <= 1) return null
  return (
    <Stack spacing={1} sx={{ alignItems: 'center', mt: 2 }}>
      <Pagination
        color="primary"
        count={pagination.total_pages}
        page={page}
        onChange={(_, p) => onChange(p)}
      />
      <Typography variant="body2" color="text.secondary">
        {pagination.count} users
      </Typography>
    </Stack>
  )
}
