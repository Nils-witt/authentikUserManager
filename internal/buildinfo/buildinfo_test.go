package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	vcs := func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.modified", Value: "true"},
		}}, true
	}
	none := func() (*debug.BuildInfo, bool) { return nil, false }

	tests := []struct {
		name        string
		commit, tag string
		read        func() (*debug.BuildInfo, bool)
		want        Info
	}{
		{
			name:   "linker values win",
			commit: "def456",
			tag:    "v1.2.3",
			read:   vcs,
			want:   Info{Repository: RepositoryURL, Commit: "def456", Tag: "v1.2.3"},
		},
		{
			name: "falls back to vcs stamp",
			read: vcs,
			want: Info{Repository: RepositoryURL, Commit: "abc123", Modified: true},
		},
		{
			name: "unknown",
			read: none,
			want: Info{Repository: RepositoryURL},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resolve(tt.commit, tt.tag, tt.read); got != tt.want {
				t.Errorf("resolve() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
