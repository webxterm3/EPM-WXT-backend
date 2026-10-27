package store

import (
	"os"
	"strings"
	"testing"
)

func readFileForTest(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("could not read %s: %v", rel, err)
	}
	return string(b)
}

func containsText(src, want string) bool { return strings.Contains(src, want) }

func countOutside(src, want string) int { return strings.Count(src, want) }
