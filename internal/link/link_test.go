package link

import (
	"strings"
	"testing"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/users"
)

const (
	testPrivateKey = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
	testShortID    = "0123456789abcdef"
)

func TestUserLinksFollowConfigOrder(t *testing.T) {
	cfg := &config.Config{
		Role:        config.RoleMain,
		HTTPListen:  config.DefaultHTTPListen,
		Certificate: testCertificate(),
		Inbound: config.Inbound{
			Listen:     ":8443",
			ServerName: "main.example.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
		},
		Routes: []config.RouteEntry{
			{ID: 1, Name: "local", Title: "Local", Outbound: config.Outbound{Type: config.OutboundTypeFreedom}},
			{ID: 2, Name: "relay", Title: "Relay", Outbound: config.Outbound{Type: config.OutboundTypeFreedom}},
		},
	}
	user := users.User{
		Username: "alice",
		Token:    "token-1",
		Clients: []users.Client{
			{Route: "relay", UUID: "aaaaaaaa-bbbb-0002-dddd-eeeeeeeeeeee"},
			{Route: "local", UUID: "aaaaaaaa-bbbb-0001-dddd-eeeeeeeeeeee"},
		},
	}

	links, err := UserLinks(cfg, user)
	if err != nil {
		t.Fatalf("UserLinks() error = %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("len(UserLinks()) = %d, want 2", len(links))
	}
	if !strings.Contains(links[0], "aaaaaaaa-bbbb-0001-dddd-eeeeeeeeeeee") || !strings.Contains(links[0], "#alice%20Local") {
		t.Fatalf("first link = %q, want local route first", links[0])
	}
	if !strings.Contains(links[1], "aaaaaaaa-bbbb-0002-dddd-eeeeeeeeeeee") || !strings.Contains(links[1], "#alice%20Relay") {
		t.Fatalf("second link = %q, want relay route second", links[1])
	}
	if !strings.Contains(links[0], "sid=0123456789abcdef") || !strings.Contains(links[0], "security=reality") {
		t.Fatalf("first link = %q, want reality params", links[0])
	}
}

func TestProfileURLOmitsDefaultPort(t *testing.T) {
	cfg := &config.Config{
		Role:        config.RoleMain,
		Certificate: testCertificate(),
		Inbound: config.Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
		},
	}

	got, err := ProfileURL(cfg, "token-1")
	if err != nil {
		t.Fatalf("ProfileURL() error = %v", err)
	}
	want := "https://main.example.com/profile/token-1"
	if got != want {
		t.Fatalf("ProfileURL() = %q, want %q", got, want)
	}
}

func testCertificate() config.Certificate {
	return config.Certificate{
		CacheDir: config.DefaultCertCache,
		CADirURL: config.DefaultCADirURL,
	}
}
