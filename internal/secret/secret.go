package secret

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	shortIDBytes = 8
	tokenBytes   = 18
)

func GenerateX25519(r io.Reader) (privateKey string, publicKey string, err error) {
	rawPrivate := make([]byte, 32)
	if _, err = io.ReadFull(r, rawPrivate); err != nil {
		return "", "", fmt.Errorf("read x25519 entropy: %w", err)
	}

	// Match xray's command behavior and store the clamped private key directly.
	rawPrivate[0] &= 248
	rawPrivate[31] &= 127
	rawPrivate[31] |= 64

	key, err := ecdh.X25519().NewPrivateKey(rawPrivate)
	if err != nil {
		return "", "", fmt.Errorf("build x25519 private key: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(rawPrivate),
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		nil
}

func PublicKeyFromPrivate(privateKey string) (string, error) {
	rawPrivate, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(rawPrivate)
	if err != nil {
		return "", fmt.Errorf("build x25519 private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func GenerateShortID(r io.Reader) (string, error) {
	buf := make([]byte, shortIDBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read short id entropy: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func GenerateToken(r io.Reader) (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read token entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func GenerateRouteID(existing map[uint16]struct{}, r io.Reader) (uint16, error) {
	var buf [2]byte
	for {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, fmt.Errorf("read route id entropy: %w", err)
		}
		id := uint16(buf[0])<<8 | uint16(buf[1])
		if id == 0 {
			continue
		}
		if _, ok := existing[id]; ok {
			continue
		}
		return id, nil
	}
}
