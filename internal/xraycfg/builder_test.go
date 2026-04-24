package xraycfg

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/users"
	"github.com/xtls/xray-core/infra/conf/serial"
)

const (
	testPrivateKey = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
	testPublicKey  = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM"
	testShortID    = "0123456789abcdef"
)

func TestBuildJSONMainConfigParsesInXray(t *testing.T) {
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
			{
				ID:    2,
				Name:  "relay",
				Title: "relay",
				Outbound: config.Outbound{
					Type:       config.OutboundTypeRelay,
					Address:    "relay.example.com",
					Port:       443,
					ServerName: "main.example.com",
					PublicKey:  testPublicKey,
					ShortID:    testShortID,
					UUID:       "aaaaaaaa-bbbb-0002-dddd-eeeeeeeeeeee",
				},
			},
		},
	}
	file := &users.File{
		Users: []users.User{
			{
				Username: "alice",
				Token:    "token-1",
				Clients: []users.Client{
					{Route: "local", UUID: "aaaaaaaa-bbbb-0001-dddd-eeeeeeeeeeee"},
					{Route: "relay", UUID: "aaaaaaaa-bbbb-0002-dddd-eeeeeeeeeeee"},
				},
			},
		},
	}

	data, err := BuildJSON(cfg, file)
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if _, err := serial.LoadJSONConfig(bytes.NewReader(data)); err != nil {
		t.Fatalf("serial.LoadJSONConfig() error = %v", err)
	}

	var root rootConfig
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	got := root.Inbounds[0].StreamSettings.RealitySettings.Dest
	if got != "127.0.0.1:8080" {
		t.Fatalf("reality dest = %q, want local HTTPS target", got)
	}
	if root.Log.LogLevel != config.DefaultLogLevel {
		t.Fatalf("loglevel = %q, want %q", root.Log.LogLevel, config.DefaultLogLevel)
	}
	clients := root.Inbounds[0].Settings.Clients
	if len(clients) != 2 {
		t.Fatalf("len(clients) = %d, want 2", len(clients))
	}
	wantEmails := map[string]bool{
		"alice@local": false,
		"alice@relay": false,
	}
	for _, client := range clients {
		if _, ok := wantEmails[client.Email]; !ok {
			t.Fatalf("unexpected client email %q", client.Email)
		}
		if wantEmails[client.Email] {
			t.Fatalf("duplicate client email %q", client.Email)
		}
		wantEmails[client.Email] = true
	}
	for email, seen := range wantEmails {
		if !seen {
			t.Fatalf("missing client email %q", email)
		}
	}
}

func TestBuildJSONOutConfigParsesInXray(t *testing.T) {
	cfg := &config.Config{
		Role: config.RoleOut,
		Inbound: config.Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
			Dest:       "main.example.com:443",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
			RelayUUID:  "aaaaaaaa-bbbb-0002-dddd-eeeeeeeeeeee",
		},
	}

	data, err := BuildJSON(cfg, nil)
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if _, err := serial.LoadJSONConfig(bytes.NewReader(data)); err != nil {
		t.Fatalf("serial.LoadJSONConfig() error = %v", err)
	}

	var root rootConfig
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	got := root.Inbounds[0].StreamSettings.RealitySettings.Dest
	if got != "main.example.com:443" {
		t.Fatalf("reality dest = %q, want main public address", got)
	}
	serverNames := root.Inbounds[0].StreamSettings.RealitySettings.ServerNames
	if len(serverNames) != 1 || serverNames[0] != "main.example.com" {
		t.Fatalf("serverNames = %v, want [main.example.com]", serverNames)
	}
}

func TestBuildJSONPassesLogLevel(t *testing.T) {
	cfg := &config.Config{
		Role:     config.RoleOut,
		LogLevel: "error",
		Inbound: config.Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
			Dest:       "main.example.com:443",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
			RelayUUID:  "aaaaaaaa-bbbb-0002-dddd-eeeeeeeeeeee",
		},
	}

	data, err := BuildJSON(cfg, nil)
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}

	var root rootConfig
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if root.Log.LogLevel != "error" {
		t.Fatalf("loglevel = %q, want error", root.Log.LogLevel)
	}
}

func testCertificate() config.Certificate {
	return config.Certificate{
		HTTPListen: config.DefaultCertHTTPListen,
		CacheDir:   config.DefaultCertCache,
		CADirURL:   config.DefaultCADirURL,
	}
}
