package zip

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTrailingDotsSupport(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Trailing dots issue is primarily a Windows API quirk")
	}

	tempDir := t.TempDir()

	dotDirPath := filepath.Join(tempDir, "folder.")
	err := os.Mkdir(fixOSPath(dotDirPath), 0755)
	if err != nil {
		t.Fatalf("Failed to MkDir with trailing dot: %v", err)
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read temp dir: %v", err)
	}
	foundDir := false
	for _, e := range entries {
		if e.Name() == "folder." {
			foundDir = true
			break
		}
	}
	if !foundDir {
		t.Fatalf("Could not find 'folder.' in directory listing")
	}

	dotFilePath := filepath.Join(dotDirPath, "file.")
	f, err := os.Create(fixOSPath(dotFilePath))
	if err != nil {
		t.Fatalf("Failed to Create file with trailing dot: %v", err)
	}
	f.Write([]byte("test"))
	f.Close()

	_, err = os.Stat(fixOSPath(dotFilePath))
	if err != nil {
		t.Fatalf("Failed to Stat file with trailing dot: %v", err)
	}
}