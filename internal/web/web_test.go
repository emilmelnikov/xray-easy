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
		Role:              config.RoleMain,
		HTTPListen:        config.DefaultHTTPListen,
		SubscriptionTitle: "Main VPN",
		Certificate:       testCertificate(),
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
		for _, scheme := range []string{"streisand://", "karing://", "foxray://", "v2box://", "sing-box://", "sub://", "sn://", "v2rayng://", "clashx://", "clash://", "flclash://", "hiddify://", "happ://"} {
			if !strings.Contains(string(body), scheme) {
				t.Fatalf("profile body = %q, want deeplink scheme %q", string(body), scheme)
			}
		}
	})

	t.Run("profile in russian", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/profile/token-1", nil)
		req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		text := string(body)
		if rec.Code != http.StatusOK {
			t.Fatalf("profile status = %d, want %d", rec.Code, http.StatusOK)
		}
		if !strings.Contains(text, `<html lang="ru">`) || !strings.Contains(text, "Личный профиль доступа") || !strings.Contains(text, "Скопировать ссылку") {
			t.Fatalf("profile body = %q, want russian profile text", text)
		}
		if strings.Contains(text, "#ZgotmplZ") {
			t.Fatalf("profile body contains blocked data URL marker: %q", text)
		}
		if !strings.Contains(text, `href="/profile/token-1?lang=en"`) || !strings.Contains(text, `href="/profile/token-1?lang=ru"`) {
			t.Fatalf("profile body = %q, want language selection links", text)
		}
	})

	t.Run("profile language query overrides header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/profile/token-1?lang=en", nil)
		req.Header.Set("Accept-Language", "ru")
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		text := string(body)
		if rec.Code != http.StatusOK {
			t.Fatalf("profile status = %d, want %d", rec.Code, http.StatusOK)
		}
		if !strings.Contains(text, `<html lang="en">`) || !strings.Contains(text, "Private access profile") {
			t.Fatalf("profile body = %q, want english profile text", text)
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
		for _, want := range []string{
			"#profile-update-interval: 24",
			"#profile-title: Main VPN",
			"#profile-web-page-url: https://main.example.com/profile/token-1",
			"vless://",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("subscription body = %q, want %q", text, want)
			}
		}
	})

	t.Run("subscription uses configured update interval", func(t *testing.T) {
		original := cfg.ProfileUpdateInterval
		cfg.ProfileUpdateInterval = 8
		defer func() { cfg.ProfileUpdateInterval = original }()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sub/token-1", nil)
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		text := string(body)
		if rec.Code != http.StatusOK {
			t.Fatalf("subscription status = %d, want %d", rec.Code, http.StatusOK)
		}
		if !strings.Contains(text, "#profile-update-interval: 8") {
			t.Fatalf("subscription body = %q, want configured update interval", text)
		}
	})

	t.Run("subscription title defaults to server name", func(t *testing.T) {
		original := cfg.SubscriptionTitle
		cfg.SubscriptionTitle = ""
		defer func() { cfg.SubscriptionTitle = original }()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sub/token-1", nil)
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		text := string(body)
		if rec.Code != http.StatusOK {
			t.Fatalf("subscription status = %d, want %d", rec.Code, http.StatusOK)
		}
		if !strings.Contains(text, "#profile-title: main.example.com") {
			t.Fatalf("subscription body = %q, want default profile title", text)
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
