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

func TestMainHandlerServesProfileAndSubscription(t *testing.T) {
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

	t.Run("landing", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("landing status = %d, want %d", rec.Code, http.StatusOK)
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
		if rec.Code != http.StatusNotFound {
			t.Fatalf("missing token status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

func TestOutHandlerOnlyServesLandingPage(t *testing.T) {
	cfg := &config.Config{
		Role:       config.RoleOut,
		HTTPListen: config.DefaultHTTPListen,
		Inbound: config.Inbound{
			Listen:     ":443",
			ServerName: "www.cloudflare.com",
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
	if rec.Code != http.StatusNotFound {
		t.Fatalf("out handler status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
