package runtime

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHSTSHandler(t *testing.T) {
	handler := hstsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://main.example.com/", nil)
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Strict-Transport-Security"); got != hstsHeaderValue {
		t.Fatalf("Strict-Transport-Security = %q, want %q", got, hstsHeaderValue)
	}
}
