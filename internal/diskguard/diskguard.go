package diskguard

import (
	"path/filepath"
)

type CheckFunc func(path string) (uint64, error)

func DefaultCheck(path string) (uint64, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return AvailableBytes(abs)
}
