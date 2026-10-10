import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'
import { SimpleTreeView } from '@mui/x-tree-view/SimpleTreeView'
import { TreeItem } from '@mui/x-tree-view/TreeItem'

interface Folder {
  name: string
  /** Full path, e.g. "users/staff". */
  path: string
  children: Folder[]
}

/** Item id of the "All users" entry; no real path starts with a NUL byte. */
const ALL_USERS = '\0all'

/** Builds a folder tree from flat paths, adding any missing parent folders. */
function buildTree(paths: string[]): Folder[] {
  const root: Folder = { name: '', path: '', children: [] }
  for (const path of paths) {
    let node = root
    for (const name of path.split('/').filter(Boolean)) {
      const childPath = node.path ? `${node.path}/${name}` : name
      let child = node.children.find((c) => c.name === name)
      if (!child) {
        child = { name, path: childPath, children: [] }
        node.children.push(child)
      }
      node = child
    }
  }
  const sort = (folders: Folder[]) => {
    folders.sort((a, b) => a.name.localeCompare(b.name))
    folders.forEach((f) => sort(f.children))
  }
  sort(root.children)
  return root.children
}

/** Returns the paths of all folders containing path, e.g. ["a", "a/b"] for "a/b/c". */
function ancestors(path: string | null): string[] {
  if (path === null) return []
  const parts = path.split('/')
  return parts.slice(0, -1).map((_, i) => parts.slice(0, i + 1).join('/'))
}

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

function FolderItem({ folder }: { folder: Folder }) {
  return (
    <TreeItem itemId={folder.path} label={folder.name} title={folder.path}>
      {folder.children.map((child) => (
        <FolderItem key={child.path} folder={child} />
      ))}
    </TreeItem>
  )
}
