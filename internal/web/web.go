// Package web embeds the built frontend so the binary is self-contained.
//
// The files under dist/ are produced by `make build-frontend` (Vite writes its
// output here, see frontend/vite.config.ts) and must exist before compiling.
package web

import (
	"embed"
	"fmt"
	"io/fs"
)

// The all: prefix keeps files starting with "_" or ".", which Vite may emit as chunk names.
//
//go:embed all:dist
var dist embed.FS

// Dist returns the embedded frontend rooted at the build output directory,
// so index.html is at the top level.
func Dist() (fs.FS, error) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, fmt.Errorf("opening embedded frontend: %w", err)
	}
	return sub, nil
}
