package fileserver

import (
	"log"
	"path/filepath"
	"testing"
)

func TestResolvePathRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	handler, err := New(root, log.Default())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []string{
		"/../secret.txt",
		"/nested/../../secret.txt",
		"..\\secret.txt",
	}

	for _, requestPath := range tests {
		t.Run(requestPath, func(t *testing.T) {
			if _, err := handler.resolvePath(requestPath); err == nil {
				t.Fatalf("resolvePath(%q) succeeded, want traversal rejection", requestPath)
			}
		})
	}
}

func TestResolvePathNormalizesWithinRoot(t *testing.T) {
	root := t.TempDir()
	handler, err := New(root, log.Default())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	target, err := handler.resolvePath("/nested/./file.txt")
	if err != nil {
		t.Fatalf("resolvePath() error = %v", err)
	}

	want := filepath.Join(root, "nested", "file.txt")
	if target != want {
		t.Fatalf("resolvePath() = %q, want %q", target, want)
	}
}
