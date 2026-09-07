//go:build windows

package diskguard

import (
	"golang.org/x/sys/windows"
)

func AvailableBytes(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes); err != nil {
		return 0, err
	}
	return freeBytesAvailable, nil
}
