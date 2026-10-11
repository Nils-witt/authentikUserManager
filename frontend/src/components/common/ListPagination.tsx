import Pagination from '@mui/material/Pagination'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import type { Pagination as PageInfo } from '../../api'

interface ListPaginationProps {
  /** Paging info of the loaded list, or undefined before the first load. */
  pagination: PageInfo | undefined
  page: number
  onChange: (page: number) => void
  /** What the list holds, in the plural, e.g. "users". */
  noun: string
}

/** Page switcher and entry count below a table; hidden for a single page. */
export function ListPagination({ pagination, page, onChange, noun }: ListPaginationProps) {
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
        {pagination.count} {noun}
      </Typography>
    </Stack>
  )
}
