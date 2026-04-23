package uuidroute

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

func Generate(routeID uint16, r io.Reader) (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return "", fmt.Errorf("read uuid entropy: %w", err)
	}
	raw[6] = byte(routeID >> 8)
	raw[7] = byte(routeID)
	return Format(raw), nil
}

func ExtractRouteID(value string) (uint16, error) {
	raw, err := Parse(value)
	if err != nil {
		return 0, err
	}
	return uint16(raw[6])<<8 | uint16(raw[7]), nil
}

func Parse(value string) ([16]byte, error) {
	var raw [16]byte
	normalized := strings.ReplaceAll(value, "-", "")
	if len(normalized) != 32 {
		return raw, fmt.Errorf("invalid uuid %q", value)
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		return raw, fmt.Errorf("invalid uuid %q", value)
	}
	copy(raw[:], decoded)
	return raw, nil
}

func Format(raw [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		raw[0:4],
		raw[4:6],
		raw[6:8],
		raw[8:10],
		raw[10:16],
	)
}
