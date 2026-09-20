//go:build windows

package queue

import (
	"golang.org/x/sys/windows"
)

func availableBytes(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var available, total, free uint64
	err = windows.GetDiskFreeSpaceEx(p, &available, &total, &free)
	return available, err
}

// Windows directory handles do not support File.Sync; SQLite FULL synchronous
// and the explicitly flushed archive file provide the platform durability path.
func syncDirectory(path string) error { return nil }
