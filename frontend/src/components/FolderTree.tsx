import { useState } from 'react'

interface Folder {
  name: string
  /** Full path, e.g. "users/staff". */
  path: string
  children: Folder[]
}

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
    <nav className="sidebar" aria-label="User folders">
      <h2>Folders</h2>
      <ul className="tree" role="tree">
        <li role="treeitem" aria-selected={selected === null}>
          <button
            type="button"
            className={selected === null ? 'folder selected' : 'folder'}
            onClick={() => onSelect(null)}
          >
            All users
          </button>
        </li>
        {tree.map((folder) => (
          <FolderNode key={folder.path} folder={folder} selected={selected} onSelect={onSelect} />
        ))}
      </ul>
    </nav>
  )
}

function FolderNode({
  folder,
  selected,
  onSelect,
}: {
  folder: Folder
  selected: string | null
  onSelect: (path: string) => void
}) {
  // Start expanded when the selection is inside this folder.
  const [open, setOpen] = useState(
    () => selected !== null && selected.startsWith(`${folder.path}/`),
  )
  const hasChildren = folder.children.length > 0
  const isSelected = selected === folder.path

  return (
    <li role="treeitem" aria-selected={isSelected} aria-expanded={hasChildren ? open : undefined}>
      <span className="folder-row">
        {hasChildren ? (
          <button
            type="button"
            className="toggle"
            aria-label={open ? `Collapse ${folder.name}` : `Expand ${folder.name}`}
            onClick={() => setOpen((o) => !o)}
          >
            {open ? '▾' : '▸'}
          </button>
        ) : (
          <span className="toggle" aria-hidden="true" />
        )}
        <button
          type="button"
          className={isSelected ? 'folder selected' : 'folder'}
          title={folder.path}
          onClick={() => {
            onSelect(folder.path)
            if (hasChildren) setOpen(true)
          }}
        >
          {folder.name}
        </button>
      </span>
      {hasChildren && open && (
        <ul role="group">
          {folder.children.map((child) => (
            <FolderNode key={child.path} folder={child} selected={selected} onSelect={onSelect} />
          ))}
        </ul>
      )}
    </li>
  )
}
