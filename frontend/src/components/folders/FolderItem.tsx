import { TreeItem } from '@mui/x-tree-view/TreeItem'
import type { Folder } from './folderPaths'

/** A folder and, recursively, its subfolders. */
export function FolderItem({ folder }: { folder: Folder }) {
  return (
    <TreeItem itemId={folder.path} label={folder.name} title={folder.path}>
      {folder.children.map((child) => (
        <FolderItem key={child.path} folder={child} />
      ))}
    </TreeItem>
  )
}
