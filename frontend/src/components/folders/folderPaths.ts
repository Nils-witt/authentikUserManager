export interface Folder {
  name: string
  /** Full path, e.g. "users/staff". */
  path: string
  children: Folder[]
}

/** Builds a folder tree from flat paths, adding any missing parent folders. */
export function buildTree(paths: string[]): Folder[] {
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
export function ancestors(path: string | null): string[] {
  if (path === null) return []
  const parts = path.split('/')
  return parts.slice(0, -1).map((_, i) => parts.slice(0, i + 1).join('/'))
}
