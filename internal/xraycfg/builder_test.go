package xraycfg

import (
	"bytes"
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
		Role:       config.RoleMain,
		HTTPListen: config.DefaultHTTPListen,
		Inbound: config.Inbound{
			Listen:     ":443",
			PublicHost: "main.example.com",
			ServerName: "www.cloudflare.com",
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
					ServerName: "www.cloudflare.com",
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
}

func TestBuildJSONOutConfigParsesInXray(t *testing.T) {
	cfg := &config.Config{
		Role:       config.RoleOut,
		HTTPListen: config.DefaultHTTPListen,
		Inbound: config.Inbound{
			Listen:     ":443",
			ServerName: "www.cloudflare.com",
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
}
