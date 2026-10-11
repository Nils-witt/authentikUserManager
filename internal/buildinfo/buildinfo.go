// Package buildinfo reports which source the running binary was built from.
//
// Release builds set the variables with the linker, for example:
//
//	go build -ldflags "-X authentikManager/internal/buildinfo.commit=$(git rev-parse HEAD) \
//	  -X authentikManager/internal/buildinfo.tag=$(git describe --tags --exact-match)"
//
// Without them, the commit falls back to the VCS revision the go command
// stamps into binaries built inside a git checkout.
package buildinfo

import "runtime/debug"

// RepositoryURL is the source repository of the application.
const RepositoryURL = "https://github.com/Nils-witt/authentikUserManager"

// Set with -ldflags "-X ...". Empty when unknown.
var (
	commit string
	tag    string
)

// Info describes the build of the running binary.
type Info struct {
	// Repository is the URL of the source repository.
	Repository string `json:"repository"`
	// Commit is the full git commit hash; empty when unknown.
	Commit string `json:"commit"`
	// Tag is the release tag, e.g. "v1.2.3"; empty for untagged builds.
	Tag string `json:"tag"`
	// Modified is set when the binary was built from a checkout with uncommitted changes.
	Modified bool `json:"modified"`
}

// Get returns the build information of the running binary.
func Get() Info {
	return resolve(commit, tag, debug.ReadBuildInfo)
}

// resolve prefers the linker-set values and falls back to the VCS settings of read.
func resolve(commit, tag string, read func() (*debug.BuildInfo, bool)) Info {
	info := Info{Repository: RepositoryURL, Commit: commit, Tag: tag}
	if info.Commit != "" {
		return info
	}
	bi, ok := read()
	if !ok {
		return info
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			info.Commit = s.Value
		case "vcs.modified":
			info.Modified = s.Value == "true"
		}
	}
	return info
}
