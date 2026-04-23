package config

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	testPrivateKey = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
	testPublicKey  = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM"
	testShortID    = "0123456789abcdef"
	testUUID       = "aaaaaaaa-bbbb-0001-dddd-eeeeeeeeeeee"
)

func TestValidateMainDuplicateRouteName(t *testing.T) {
	cfg := &Config{
		Role:       RoleMain,
		HTTPListen: DefaultHTTPListen,
		Inbound: Inbound{
			Listen:     ":443",
			PublicHost: "main.example.com",
			ServerName: "www.cloudflare.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
		},
		Routes: []RouteEntry{
			{ID: 1, Name: "local", Title: "local", Outbound: Outbound{Type: OutboundTypeFreedom}},
			{ID: 2, Name: "local", Title: "relay", Outbound: Outbound{Type: OutboundTypeFreedom}},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want duplicate route name error")
	}
}

func TestValidateOutRelayUUID(t *testing.T) {
	cfg := &Config{
		Role:       RoleOut,
		HTTPListen: DefaultHTTPListen,
		Inbound: Inbound{
			Listen:     ":443",
			ServerName: "www.cloudflare.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
			RelayUUID:  "not-a-uuid",
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want invalid relay UUID error")
	}
}

func TestValidateRelayOutbound(t *testing.T) {
	cfg := &Config{
		Role:       RoleMain,
		HTTPListen: DefaultHTTPListen,
		Inbound: Inbound{
			Listen:     ":443",
			PublicHost: "main.example.com",
			ServerName: "www.cloudflare.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
		},
		Routes: []RouteEntry{
			{
				ID:    1,
				Name:  "relay",
				Title: "relay",
				Outbound: Outbound{
					Type:       OutboundTypeRelay,
					Address:    "relay.example.com",
					Port:       443,
					ServerName: "www.cloudflare.com",
					PublicKey:  testPublicKey,
					ShortID:    testShortID,
					UUID:       testUUID,
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestConfigJSONUsesSnakeCaseKeys(t *testing.T) {
	cfg := &Config{
		Role:       RoleMain,
		HTTPListen: DefaultHTTPListen,
		Inbound: Inbound{
			Listen:     ":443",
			PublicHost: "main.example.com",
			ServerName: "www.cloudflare.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
		},
		Routes: []RouteEntry{
			{
				ID:    1,
				Name:  "relay",
				Title: "relay",
				Outbound: Outbound{
					Type:       OutboundTypeRelay,
					Address:    "relay.example.com",
					Port:       443,
					ServerName: "www.cloudflare.com",
					PublicKey:  testPublicKey,
					ShortID:    testShortID,
					UUID:       testUUID,
				},
			},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	text := string(data)
	for _, key := range []string{
		`"http_listen"`,
		`"public_host"`,
		`"server_name"`,
		`"private_key"`,
		`"short_id"`,
		`"public_key"`,
	} {
		if !strings.Contains(text, key) {
			t.Fatalf("marshaled config missing key %s: %s", key, text)
		}
	}
	for _, key := range []string{
		`"httpListen"`,
		`"publicHost"`,
		`"serverName"`,
		`"privateKey"`,
		`"shortId"`,
		`"publicKey"`,
	} {
		if strings.Contains(text, key) {
			t.Fatalf("marshaled config contains camelCase key %s: %s", key, text)
		}
	}
}
