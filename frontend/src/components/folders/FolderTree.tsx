import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'
import { SimpleTreeView } from '@mui/x-tree-view/SimpleTreeView'
import { TreeItem } from '@mui/x-tree-view/TreeItem'
import { FolderItem } from './FolderItem'
import { ancestors, buildTree } from './folderPaths'

/** Item id of the "All …" entry; no real path starts with a NUL byte. */
const ALL = '\0all'

interface FolderTreeProps {
  paths: string[]
  /** The selected folder, or null for everything. */
  selected: string | null
  onSelect: (path: string | null) => void
  /** What the folders hold, in the plural; defaults to "users". */
  noun?: string
}

/** Sidebar listing folders (paths) as a collapsible tree. */
export function FolderTree({ paths, selected, onSelect, noun = 'users' }: FolderTreeProps) {
  const tree = buildTree(paths)
  return (
    <Paper
      component="nav"
      variant="outlined"
      aria-label={`Folders of ${noun}`}
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
        selectedItems={selected ?? ALL}
        onSelectedItemsChange={(_, id) => {
          if (id !== null) onSelect(id === ALL ? null : id)
        }}
        defaultExpandedItems={ancestors(selected)}
      >
        <TreeItem itemId={ALL} label={`All ${noun}`} />
        {tree.map((folder) => (
          <FolderItem key={folder.path} folder={folder} />
        ))}
      </SimpleTreeView>
    </Paper>
  )
}
