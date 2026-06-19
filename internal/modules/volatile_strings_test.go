//go:build linux

package modules

import (
	"strings"
	"testing"
)

func TestExtractStrings_FindsLongRuns(t *testing.T) {
	input := []byte("AB\x00\x00hello world\x00short\x00another long string here\x00")
	result := extractStrings(input, 8)
	if !strings.Contains(result, "hello world") {
		t.Error("expected 'hello world' (11 chars) in output")
	}
	if strings.Contains(result, "short") {
		t.Error("'short' is 5 chars, below minLen=8, must not appear")
	}
	if !strings.Contains(result, "another long string here") {
		t.Error("expected 'another long string here' in output")
	}
}

func TestExtractStrings_EmptyInput(t *testing.T) {
	result := extractStrings([]byte{}, 8)
	if result != "" {
		t.Errorf("expected empty output for empty input, got %q", result)
	}
}

func TestExtractStrings_AllBinary(t *testing.T) {
	input := []byte{0x00, 0x01, 0x02, 0x7f, 0x80, 0xff}
	result := extractStrings(input, 4)
	if result != "" {
		t.Errorf("expected empty output for all-binary input, got %q", result)
	}
}

func TestExtractStrings_ExactMinLen(t *testing.T) {
	// exactly minLen chars should be included
	input := []byte("12345678\x00")
	result := extractStrings(input, 8)
	if !strings.Contains(result, "12345678") {
		t.Errorf("expected run of exactly minLen to be included, got %q", result)
	}
}

func TestExtractStrings_OneBelowMinLen(t *testing.T) {
	input := []byte("1234567\x00")
	result := extractStrings(input, 8)
	if strings.Contains(result, "1234567") {
		t.Errorf("run of minLen-1 must not appear, got %q", result)
	}
}
