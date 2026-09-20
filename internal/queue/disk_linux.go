//go:build linux

package queue

import (
	"golang.org/x/sys/unix"
	"os"
)

func availableBytes(path string) (uint64, error) {
	var s unix.Statfs_t
	err := unix.Statfs(path, &s)
	return uint64(s.Bavail) * uint64(s.Bsize), err
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
