//go:build !linux && !windows

package queue

import "fmt"

func availableBytes(path string) (uint64, error) {
	return 0, fmt.Errorf("disk metrics unsupported on this platform")
}
func syncDirectory(path string) error {
	return fmt.Errorf("durable archive publication unsupported on this platform")
}
