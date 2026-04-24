package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/link"
	"github.com/emilmelnikov/xray-easy/internal/users"
)

const (
	testPrivateKey = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
	testShortID    = "0123456789abcdef"
)

func TestRunInitConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x11}, 64))

	err := run([]string{
		"init-config",
		"-output", configPath,
		"-server-name", "main.example.com",
	}, &stdout, &stderr, entropy)
	if err != nil {
		t.Fatalf("run(init-config) error = %v, stderr = %q", err, stderr.String())
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if cfg.Role != config.RoleMain {
		t.Fatalf("cfg.Role = %q, want %q", cfg.Role, config.RoleMain)
	}

	file, err := users.Load(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatalf("users.Load() error = %v", err)
	}
	if len(file.Users) != 0 {
		t.Fatalf("len(users) = %d, want 0", len(file.Users))
	}
}

func TestRunAddUser(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	usersPath := filepath.Join(dir, "users.json")

	cfg := &config.Config{
		Role:        config.RoleMain,
		HTTPListen:  config.DefaultHTTPListen,
		Certificate: testCertificate(),
		Inbound: config.Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
		},
		Routes: []config.RouteEntry{
			{ID: 1, Name: "local", Title: "local", Outbound: config.Outbound{Type: config.OutboundTypeFreedom}},
		},
	}
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("config.Save() error = %v", err)
	}
	if err := users.Save(usersPath, &users.File{Users: []users.User{}}); err != nil {
		t.Fatalf("users.Save() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x22}, 64))

	err := run([]string{
		"add-user",
		"-config", configPath,
		"-users", usersPath,
		"alice",
	}, &stdout, &stderr, entropy)
	if err != nil {
		t.Fatalf("run(add-user) error = %v, stderr = %q", err, stderr.String())
	}

	file, err := users.Load(usersPath)
	if err != nil {
		t.Fatalf("users.Load() error = %v", err)
	}
	if len(file.Users) != 1 {
		t.Fatalf("len(users) = %d, want 1", len(file.Users))
	}
	if err := file.Validate(cfg); err != nil {
		t.Fatalf("users.Validate() error = %v", err)
	}

	wantURL, err := link.ProfileURL(cfg, file.Users[0].Token)
	if err != nil {
		t.Fatalf("ProfileURL() error = %v", err)
	}
	if strings.TrimSpace(stdout.String()) != wantURL {
		t.Fatalf("stdout = %q, want %q", strings.TrimSpace(stdout.String()), wantURL)
	}
}

func TestRunAddRoute(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	usersPath := filepath.Join(dir, "users.json")

	cfg := &config.Config{
		Role:        config.RoleMain,
		HTTPListen:  config.DefaultHTTPListen,
		Certificate: testCertificate(),
		Inbound: config.Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
		},
		Routes: []config.RouteEntry{
			{ID: 1, Name: "local", Title: "local", Outbound: config.Outbound{Type: config.OutboundTypeFreedom}},
		},
	}
	file := &users.File{
		Users: []users.User{
			{
				Username: "alice",
				Token:    "token-1",
				Clients: []users.Client{
					{Route: "local", UUID: "aaaaaaaa-bbbb-0001-dddd-eeeeeeeeeeee"},
				},
			},
		},
	}
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("config.Save() error = %v", err)
	}
	if err := users.Save(usersPath, file); err != nil {
		t.Fatalf("users.Save() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	entropy := bytes.NewReader([]byte{
		0x00, 0x02, // route id
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, // x25519
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, // short id
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, // relay uuid
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, // backfilled user uuid
	})

	err := run([]string{
		"add-route",
		"-config", configPath,
		"-users", usersPath,
		"-address", "relay.example.com",
		"-port", "443",
		"relay",
	}, &stdout, &stderr, entropy)
	if err != nil {
		t.Fatalf("run(add-route) error = %v, stderr = %q", err, stderr.String())
	}

	updatedConfig, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if len(updatedConfig.Routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(updatedConfig.Routes))
	}

	updatedUsers, err := users.Load(usersPath)
	if err != nil {
		t.Fatalf("users.Load() error = %v", err)
	}
	if err := updatedUsers.Validate(updatedConfig); err != nil {
		t.Fatalf("users.Validate() error = %v", err)
	}
	if len(updatedUsers.Users[0].Clients) != 2 {
		t.Fatalf("len(user.clients) = %d, want 2", len(updatedUsers.Users[0].Clients))
	}

	var outConfig config.Config
	if err := json.Unmarshal(stdout.Bytes(), &outConfig); err != nil {
		t.Fatalf("json.Unmarshal(stdout) error = %v", err)
	}
	if outConfig.Role != config.RoleOut {
		t.Fatalf("outConfig.Role = %q, want %q", outConfig.Role, config.RoleOut)
	}
	if outConfig.Inbound.RelayUUID != updatedConfig.Routes[1].Outbound.UUID {
		t.Fatalf("outConfig relay UUID = %q, want %q", outConfig.Inbound.RelayUUID, updatedConfig.Routes[1].Outbound.UUID)
	}
	if outConfig.Inbound.ServerName != "main.example.com" {
		t.Fatalf("outConfig server name = %q, want main.example.com", outConfig.Inbound.ServerName)
	}
	if outConfig.Inbound.Dest != "main.example.com:443" {
		t.Fatalf("outConfig dest = %q, want main.example.com:443", outConfig.Inbound.Dest)
	}
	if outConfig.HTTPListen != "" {
		t.Fatalf("outConfig HTTPListen = %q, want empty", outConfig.HTTPListen)
	}
	if outConfig.Certificate != (config.Certificate{}) {
		t.Fatalf("outConfig Certificate = %+v, want empty", outConfig.Certificate)
	}
	if updatedConfig.Routes[1].Outbound.ServerName != "main.example.com" {
		t.Fatalf("relay route server name = %q, want main.example.com", updatedConfig.Routes[1].Outbound.ServerName)
	}

	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("config file stat error = %v", err)
	}
}

func testCertificate() config.Certificate {
	return config.Certificate{
		HTTPListen: config.DefaultCertHTTPListen,
		CacheDir:   config.DefaultCertCache,
		CADirURL:   config.DefaultCADirURL,
	}
}
