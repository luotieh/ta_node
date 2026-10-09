package capture

import "testing"

func TestCaptureLengthIsDistinctFromOriginal(t *testing.T) {
	info := packetCaptureInfo(1600, 2848, 3)
	if info.CaptureLength != 1600 || info.Length != 2848 {
		t.Fatalf("lost original frame length: %+v", info)
	}
	info = packetCaptureInfo(743, 743, 3)
	if info.CaptureLength != info.Length {
		t.Fatalf("short packet marked truncated: %+v", info)
	}
}
