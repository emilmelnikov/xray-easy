package users

import (
	"testing"

	"github.com/emilmelnikov/xray-easy/internal/config"
)

const (
	testPrivateKey = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
	testShortID    = "0123456789abcdef"
)

func TestValidateRequiresOneClientPerRoute(t *testing.T) {
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
			{ID: 2, Name: "relay", Title: "relay", Outbound: config.Outbound{Type: config.OutboundTypeFreedom}},
		},
	}
	file := &File{
		Users: []User{
			{
				Username: "alice",
				Token:    "token-1",
				Clients: []Client{
					{Route: "local", UUID: "aaaaaaaa-bbbb-0001-dddd-eeeeeeeeeeee"},
				},
			},
		},
	}

	if err := file.Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want missing route client error")
	}
}

func TestValidateRejectsMismatchedUUIDRouteID(t *testing.T) {
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
		},
	}
	file := &File{
		Users: []User{
			{
				Username: "alice",
				Token:    "token-1",
				Clients: []Client{
					{Route: "local", UUID: "aaaaaaaa-bbbb-0002-dddd-eeeeeeeeeeee"},
				},
			},
		},
	}

	if err := file.Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want mismatched route id error")
	}
}
