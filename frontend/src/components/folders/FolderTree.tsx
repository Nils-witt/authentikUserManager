import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'
import { SimpleTreeView } from '@mui/x-tree-view/SimpleTreeView'
import { TreeItem } from '@mui/x-tree-view/TreeItem'
import { FolderItem } from './FolderItem'
import { ancestors, buildTree } from './folderPaths'

/** Item id of the "All users" entry; no real path starts with a NUL byte. */
const ALL_USERS = '\0all'

interface FolderTreeProps {
  paths: string[]
  /** The selected folder, or null for all users. */
  selected: string | null
  onSelect: (path: string | null) => void
}

/** Sidebar listing the user folders (paths) as a collapsible tree. */
export function FolderTree({ paths, selected, onSelect }: FolderTreeProps) {
  const tree = buildTree(paths)
  return (
    <Paper
      component="nav"
      variant="outlined"
      aria-label="User folders"
      sx={{
        position: { md: 'sticky' },
        top: 16,
        maxHeight: { md: 'calc(100vh - 32px)' },
        overflowY: 'auto',
        p: 1,
      }}
    >
      <Typography variant="overline" color="text.secondary" sx={{ px: 1 }}>
        Folders
      </Typography>
      <SimpleTreeView
        selectedItems={selected ?? ALL_USERS}
        onSelectedItemsChange={(_, id) => {
          if (id !== null) onSelect(id === ALL_USERS ? null : id)
        }}
        defaultExpandedItems={ancestors(selected)}
      >
        <TreeItem itemId={ALL_USERS} label="All users" />
        {tree.map((folder) => (
          <FolderItem key={folder.path} folder={folder} />
        ))}
      </SimpleTreeView>
    </Paper>
  )
}
