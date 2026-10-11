import Box from '@mui/material/Box'
import Link from '@mui/material/Link'
import Typography from '@mui/material/Typography'
import { Fragment, useEffect, useState, type ReactNode } from 'react'
import * as api from '../../api'
import type { BuildInfo } from '../../api'

/** Length of the abbreviated commit hash. */
const shortCommitLength = 12

/** Year shown in the copyright, taken when the app loads. */
const copyrightYear = new Date().getFullYear()

function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} target="_blank" rel="noopener noreferrer" color="inherit">
      {children}
    </Link>
  )
}

/** Copyright line with the release tag, repository and commit the server was built from. */
export function AppFooter() {
  const [info, setInfo] = useState<BuildInfo | null>(null)

  useEffect(() => {
    // Build details are optional; without them only the copyright and app name show.
    api
      .version()
      .then(setInfo)
      .catch(() => {})
  }, [])

  const repo = info?.repository.replace(/\/+$/, '')
  const parts: ReactNode[] = [`© ${copyrightYear} Nils Witt`, 'Authentik Manager']
  if (repo && info) {
    if (info.tag) {
      parts.push(
        <ExternalLink href={`${repo}/releases/tag/${encodeURIComponent(info.tag)}`}>
          {info.tag}
        </ExternalLink>,
      )
    }
    parts.push(<ExternalLink href={repo}>GitHub</ExternalLink>)
    if (info.commit) {
      parts.push(
        <ExternalLink href={`${repo}/commit/${info.commit}`}>
          {info.commit.slice(0, shortCommitLength)}
          {info.modified && '-dirty'}
        </ExternalLink>,
      )
    }
  }

  return (
    <Box
      component="footer"
      sx={{ borderTop: 1, borderColor: 'divider', py: 2, px: 3, textAlign: 'center' }}
    >
      <Typography variant="body2" color="text.secondary">
        {parts.map((part, i) => (
          // The parts are fixed per render, so their index is a stable key.
          <Fragment key={i}>
            {i > 0 && ' · '}
            {part}
          </Fragment>
        ))}
      </Typography>
    </Box>
  )
}
