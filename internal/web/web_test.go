package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/users"
)

const (
	testPrivateKey = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
	testShortID    = "0123456789abcdef"
)

func TestMainHandlerServesAuthFallback(t *testing.T) {
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
			{ID: 1, Name: "local", Title: "Local", Outbound: config.Outbound{Type: config.OutboundTypeFreedom}},
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

	handler, err := NewHandler(cfg, file)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	t.Run("fallback redirects to auth", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("fallback status = %d, want %d", rec.Code, http.StatusFound)
		}
		if rec.Header().Get("Location") != "/auth" {
			t.Fatalf("fallback location = %q, want /auth", rec.Header().Get("Location"))
		}
	})

	t.Run("auth form", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		if rec.Code != http.StatusOK {
			t.Fatalf("auth status = %d, want %d", rec.Code, http.StatusOK)
		}
		text := string(body)
		if !strings.Contains(text, `<form method="post" action="/auth">`) || !strings.Contains(text, `type="password"`) {
			t.Fatalf("auth body = %q, want login form", text)
		}
	})

	t.Run("auth post shows invalid credentials", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader("email=alice%40example.com&password=secret"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		if rec.Code != http.StatusOK {
			t.Fatalf("auth post status = %d, want %d", rec.Code, http.StatusOK)
		}
		text := string(body)
		if !strings.Contains(text, "Invalid email or password.") || !strings.Contains(text, "alice@example.com") {
			t.Fatalf("auth post body = %q, want invalid credentials and submitted email", text)
		}
	})

	t.Run("profile", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/profile/token-1", nil)
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		if rec.Code != http.StatusOK {
			t.Fatalf("profile status = %d, want %d", rec.Code, http.StatusOK)
		}
		if !strings.Contains(string(body), "alice") || !strings.Contains(string(body), "/sub/token-1") {
			t.Fatalf("profile body = %q, want username and subscription link", string(body))
		}
		if strings.Contains(string(body), "#ZgotmplZ") {
			t.Fatalf("profile body contains blocked data URL marker: %q", string(body))
		}
		if !strings.Contains(string(body), `src="data:image/png;base64,`) {
			t.Fatalf("profile body = %q, want inline QR code data URL", string(body))
		}
	})

	t.Run("subscription", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sub/token-1", nil)
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		if rec.Code != http.StatusOK {
			t.Fatalf("subscription status = %d, want %d", rec.Code, http.StatusOK)
		}
		text := string(body)
		if !strings.Contains(text, "#profile-title: alice") || !strings.Contains(text, "vless://") {
			t.Fatalf("subscription body = %q, want profile header and vless link", text)
		}
	})

	t.Run("missing token", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/profile/missing", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("missing token status = %d, want %d", rec.Code, http.StatusFound)
		}
		if rec.Header().Get("Location") != "/auth" {
			t.Fatalf("missing token location = %q, want /auth", rec.Header().Get("Location"))
		}
	})
}

func TestOutHandlerServesAuthFallback(t *testing.T) {
	cfg := &config.Config{
		Role:        config.RoleOut,
		HTTPListen:  config.DefaultHTTPListen,
		Certificate: testCertificate(),
		Inbound: config.Inbound{
			Listen:     ":443",
			ServerName: "relay.example.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
			RelayUUID:  "aaaaaaaa-bbbb-0001-dddd-eeeeeeeeeeee",
		},
	}

	handler, err := NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/profile/token-1", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("out handler status = %d, want %d", rec.Code, http.StatusFound)
	}
	if rec.Header().Get("Location") != "/auth" {
		t.Fatalf("out handler location = %q, want /auth", rec.Header().Get("Location"))
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	handler.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK {
		t.Fatalf("out auth status = %d, want %d", rec.Code, http.StatusOK)
	}
	if strings.Contains(strings.ToLower(string(body)), "xray") {
		t.Fatalf("out auth body exposes xray: %q", string(body))
	}
}

func testCertificate() config.Certificate {
	return config.Certificate{
		HTTPListen: config.DefaultCertHTTPListen,
		CacheDir:   config.DefaultCertCache,
		CADirURL:   config.DefaultCADirURL,
	}
}
