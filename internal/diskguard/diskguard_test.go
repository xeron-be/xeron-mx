package diskguard

import (
	"os"
	"testing"
)

func TestAvailableBytes(t *testing.T) {
	tempDir := os.TempDir()
	avail, err := AvailableBytes(tempDir)
	if err != nil {
		t.Fatalf("AvailableBytes failed on %s: %v", tempDir, err)
	}
	if avail == 0 {
		t.Fatalf("expected available bytes > 0, got %d", avail)
	}
}

func TestDefaultCheck(t *testing.T) {
	avail, err := DefaultCheck(".")
	if err != nil {
		t.Fatalf("DefaultCheck failed: %v", err)
	}
	if avail == 0 {
		t.Fatalf("expected available bytes > 0, got %d", avail)
	}
}
