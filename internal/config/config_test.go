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
		Role:        RoleMain,
		HTTPListen:  DefaultHTTPListen,
		Certificate: testCertificate(),
		Inbound: Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
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
		Role: RoleOut,
		Inbound: Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
			Dest:       "main.example.com:443",
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
		Role:        RoleMain,
		HTTPListen:  DefaultHTTPListen,
		Certificate: testCertificate(),
		Inbound: Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
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
					ServerName: "relay.example.com",
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
		Role:        RoleMain,
		HTTPListen:  DefaultHTTPListen,
		Certificate: testCertificate(),
		Inbound: Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
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
					ServerName: "relay.example.com",
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
	cfg.Normalize()
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal(normalized) error = %v", err)
	}
	text := string(data)
	for _, key := range []string{
		`"http_listen"`,
		`"loglevel"`,
		`"cache_dir"`,
		`"ca_dir_url"`,
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
		`"logLevel"`,
		`"cacheDir"`,
		`"caDirURL"`,
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

func TestNormalizeDefaultsLogLevel(t *testing.T) {
	cfg := &Config{}
	cfg.Normalize()
	if cfg.LogLevel != DefaultLogLevel {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}
}

func TestValidateDefaultsOptionalListenFields(t *testing.T) {
	cfg := &Config{
		Role: RoleMain,
		Certificate: Certificate{
			CacheDir: DefaultCertCache,
			CADirURL: DefaultCADirURL,
		},
		Inbound: Inbound{
			ServerName: "main.example.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
		},
		Routes: []RouteEntry{
			{ID: 1, Name: "local", Title: "local", Outbound: Outbound{Type: OutboundTypeFreedom}},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.Inbound.Listen != DefaultInboundListen {
		t.Fatalf("Inbound.Listen = %q, want %q", cfg.Inbound.Listen, DefaultInboundListen)
	}
	if cfg.Certificate.HTTPListen != DefaultCertHTTPListen {
		t.Fatalf("Certificate.HTTPListen = %q, want %q", cfg.Certificate.HTTPListen, DefaultCertHTTPListen)
	}
}

func TestValidateOutConfigDoesNotRequireHTTPOrCertificate(t *testing.T) {
	cfg := &Config{
		Role: RoleOut,
		Inbound: Inbound{
			ServerName: "main.example.com",
			Dest:       "main.example.com:443",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
			RelayUUID:  testUUID,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.HTTPListen != "" {
		t.Fatalf("HTTPListen = %q, want empty for out config", cfg.HTTPListen)
	}
	if cfg.Inbound.Listen != DefaultInboundListen {
		t.Fatalf("Inbound.Listen = %q, want %q", cfg.Inbound.Listen, DefaultInboundListen)
	}
	if cfg.Certificate != (Certificate{}) {
		t.Fatalf("Certificate = %+v, want empty for out config", cfg.Certificate)
	}
}

func TestValidateLogLevel(t *testing.T) {
	cfg := &Config{
		Role:     RoleOut,
		LogLevel: "verbose",
		Inbound: Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
			Dest:       "main.example.com:443",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
			RelayUUID:  testUUID,
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want invalid loglevel error")
	}
}

func testCertificate() Certificate {
	return Certificate{
		HTTPListen: DefaultCertHTTPListen,
		CacheDir:   DefaultCertCache,
		CADirURL:   DefaultCADirURL,
	}
}
