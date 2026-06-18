//go:build linux

package modules

import (
	"testing"
	"time"
)

func TestReadKmsgLinesDoesNotHang(t *testing.T) {
	done := make(chan struct{})
	go func() {
		_, _, _ = readKmsgLines()
		close(done)
	}()
	select {
	case <-done:
		// passed: function returned within deadline
	case <-time.After(5 * time.Second):
		t.Fatal("readKmsgLines hung for >5s — EAGAIN not handled correctly")
	}
}

func TestReadKmsgLinesRecordCap(t *testing.T) {
	lines, _, _ := readKmsgLines()
	if len(lines) > maxKmsgRecords {
		t.Errorf("returned %d records, exceeds cap %d", len(lines), maxKmsgRecords)
	}
}
