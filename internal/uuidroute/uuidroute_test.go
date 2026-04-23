package uuidroute

import (
	"bytes"
	"testing"
)

func TestGenerateAndExtractRouteID(t *testing.T) {
	value, err := Generate(0x1234, bytes.NewReader(bytes.Repeat([]byte{0xaa}, 16)))
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	routeID, err := ExtractRouteID(value)
	if err != nil {
		t.Fatalf("ExtractRouteID() error = %v", err)
	}
	if routeID != 0x1234 {
		t.Fatalf("ExtractRouteID() = %d, want %d", routeID, 0x1234)
	}
}

func TestParseAllowsNonRFCUUIDBits(t *testing.T) {
	raw := [16]byte{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0xab, 0xcd,
		0x80, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	value := Format(raw)
	parsed, err := Parse(value)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed != raw {
		t.Fatalf("Parse() = %v, want %v", parsed, raw)
	}
}
