package web

import (
	"io/fs"
	"testing"
)

func TestDistContainsIndex(t *testing.T) {
	t.Parallel()

	static, err := Dist()
	if err != nil {
		t.Fatalf("Dist() error = %v", err)
	}
	if _, err := fs.Stat(static, "index.html"); err != nil {
		t.Fatalf("embedded frontend has no index.html: %v", err)
	}
}
