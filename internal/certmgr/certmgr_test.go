package certmgr

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/go-acme/lego/v4/certificate"
)

func TestTemporaryCertificateNeedsRenewal(t *testing.T) {
	certPEM, keyPEM, err := temporaryCertificate("main.example.com")
	if err != nil {
		t.Fatalf("temporaryCertificate() error = %v", err)
	}
	if !needsRenewal(certPEM, renewBefore) {
		t.Fatal("temporary certificate should need renewal")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("temporary certificate key PEM did not decode")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseECPrivateKey() error = %v", err)
	}
	if key.Curve.Params().Name != "P-256" {
		t.Fatalf("temporary certificate key curve = %q, want P-256", key.Curve.Params().Name)
	}

	cert, err := leafCertificate(certPEM)
	if err != nil {
		t.Fatalf("leafCertificate() error = %v", err)
	}
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("temporary certificate public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
}

func TestHTTPProviderServesChallenge(t *testing.T) {
	provider := newHTTPProvider("main.example.com")
	if err := provider.Present("main.example.com", "token", "key-auth"); err != nil {
		t.Fatalf("Present() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://main.example.com/.well-known/acme-challenge/token", nil)
	provider.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, want %d", rec.Code, http.StatusOK)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(body) != "key-auth" {
		t.Fatalf("challenge body = %q, want key-auth", string(body))
	}
	if err := provider.CleanUp("main.example.com", "token", "key-auth"); err != nil {
		t.Fatalf("CleanUp() error = %v", err)
	}

	rec = httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("challenge after cleanup status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHTTPProviderRedirectsOtherRequestsToHTTPS(t *testing.T) {
	provider := newHTTPProvider("main.example.com")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://main.example.com/profile/token?x=1", nil)
	provider.ServeHTTP(rec, req)
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("redirect status = %d, want %d", rec.Code, http.StatusPermanentRedirect)
	}
	if got := rec.Header().Get("Location"); got != "https://main.example.com/profile/token?x=1" {
		t.Fatalf("Location = %q, want HTTPS redirect", got)
	}
}

func TestFallbackRenewSchedule(t *testing.T) {
	now := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		cert     *x509.Certificate
		schedule renewalSchedule
	}{
		{
			name:     "already in renewal window",
			cert:     &x509.Certificate{NotAfter: now.Add(renewBefore)},
			schedule: renewalSchedule{renew: true},
		},
		{
			name:     "before renewal window",
			cert:     &x509.Certificate{NotAfter: now.Add(renewBefore + 2*time.Hour)},
			schedule: renewalSchedule{delay: 2 * time.Hour, renew: true},
		},
		{
			name:     "polls when renewal window is far away",
			cert:     &x509.Certificate{NotAfter: now.Add(renewBefore + 48*time.Hour)},
			schedule: renewalSchedule{delay: fallbackRenewCheck},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if schedule := fallbackRenewSchedule(tt.cert, now); schedule != tt.schedule {
				t.Fatalf("fallbackRenewSchedule() = %+v, want %+v", schedule, tt.schedule)
			}
		})
	}
}

func TestARIRenewalSchedule(t *testing.T) {
	now := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		renewAt   *time.Time
		nextCheck time.Time
		schedule  renewalSchedule
	}{
		{
			name:      "retry after before renewal only checks",
			renewAt:   testTimePtr(now.Add(6 * time.Hour)),
			nextCheck: now.Add(2 * time.Hour),
			schedule:  renewalSchedule{delay: 2 * time.Hour},
		},
		{
			name:      "renewal before retry after renews",
			renewAt:   testTimePtr(now.Add(2 * time.Hour)),
			nextCheck: now.Add(6 * time.Hour),
			schedule:  renewalSchedule{delay: 2 * time.Hour, renew: true},
		},
		{
			name:      "due renewal renews immediately",
			renewAt:   testTimePtr(now.Add(-time.Minute)),
			nextCheck: now.Add(2 * time.Hour),
			schedule:  renewalSchedule{renew: true},
		},
		{
			name:      "no renewal time checks at retry after",
			nextCheck: now.Add(2 * time.Hour),
			schedule:  renewalSchedule{delay: 2 * time.Hour},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if schedule := ariRenewalSchedule(tt.renewAt, tt.nextCheck, now); schedule != tt.schedule {
				t.Fatalf("ariRenewalSchedule() = %+v, want %+v", schedule, tt.schedule)
			}
		})
	}
}

func TestRenewalMetaCacheFile(t *testing.T) {
	manager, err := New("main.example.com", testCertificateConfig(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	meta := renewalMeta{
		CertID:         "cert-id",
		RetryAfter:     "2h0m0s",
		RenewAt:        time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC),
		NextCheck:      time.Date(2026, 4, 24, 14, 0, 0, 0, time.UTC),
		ExplanationURL: "https://example.com/ari",
		LastChecked:    time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC),
	}
	if err := manager.saveRenewalMeta(meta); err != nil {
		t.Fatalf("saveRenewalMeta() error = %v", err)
	}

	data, err := os.ReadFile(manager.path("ari.json"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), `"cert_id": "cert-id"`) {
		t.Fatalf("ARI metadata did not include cert ID: %s", string(data))
	}

	if err := manager.removeRenewalMeta(); err != nil {
		t.Fatalf("removeRenewalMeta() error = %v", err)
	}
	if _, err := os.Stat(manager.path("ari.json")); !os.IsNotExist(err) {
		t.Fatalf("ARI metadata still exists after removal: %v", err)
	}
}

func TestCachedRenewalSchedule(t *testing.T) {
	manager, err := New("main.example.com", testCertificateConfig(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	certPEM, _, err := temporaryCertificate("main.example.com")
	if err != nil {
		t.Fatalf("temporaryCertificate() error = %v", err)
	}
	leaf, err := leafCertificate(certPEM)
	if err != nil {
		t.Fatalf("leafCertificate() error = %v", err)
	}
	certID, err := certificate.MakeARICertID(leaf)
	if err != nil {
		t.Fatalf("MakeARICertID() error = %v", err)
	}

	now := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	if err := manager.saveRenewalMeta(renewalMeta{
		CertID:      certID,
		RenewAt:     now.Add(4 * time.Hour),
		NextCheck:   now.Add(2 * time.Hour),
		LastChecked: now,
	}); err != nil {
		t.Fatalf("saveRenewalMeta() error = %v", err)
	}
	schedule, ok := manager.cachedRenewalSchedule(leaf, now)
	if !ok {
		t.Fatal("cachedRenewalSchedule() did not use valid cached metadata")
	}
	wantSchedule := renewalSchedule{delay: 2 * time.Hour}
	if schedule != wantSchedule {
		t.Fatalf("cachedRenewalSchedule() = %+v, want %+v", schedule, wantSchedule)
	}

	if err := manager.saveRenewalMeta(renewalMeta{
		CertID:      certID,
		RenewAt:     now.Add(-time.Minute),
		NextCheck:   now.Add(-time.Minute),
		LastChecked: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("saveRenewalMeta() expired error = %v", err)
	}
	schedule, ok = manager.cachedRenewalSchedule(leaf, now)
	if !ok {
		t.Fatal("cachedRenewalSchedule() did not use due cached metadata")
	}
	wantSchedule = renewalSchedule{renew: true}
	if schedule != wantSchedule {
		t.Fatalf("cachedRenewalSchedule() = %+v, want %+v", schedule, wantSchedule)
	}

	if err := manager.saveRenewalMeta(renewalMeta{
		CertID:      certID,
		RenewAt:     now.Add(4 * time.Hour),
		NextCheck:   now.Add(-time.Minute),
		LastChecked: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("saveRenewalMeta() stale error = %v", err)
	}
	if _, ok := manager.cachedRenewalSchedule(leaf, now); ok {
		t.Fatal("cachedRenewalSchedule() used stale metadata instead of refreshing ARI")
	}

	if err := manager.saveRenewalMeta(renewalMeta{
		CertID:      "different-cert",
		RenewAt:     now.Add(4 * time.Hour),
		NextCheck:   now.Add(2 * time.Hour),
		LastChecked: now,
	}); err != nil {
		t.Fatalf("saveRenewalMeta() mismatched error = %v", err)
	}
	if _, ok := manager.cachedRenewalSchedule(leaf, now); ok {
		t.Fatal("cachedRenewalSchedule() used metadata for a different certificate")
	}
}

func TestARICertID(t *testing.T) {
	certPEM, _, err := temporaryCertificate("main.example.com")
	if err != nil {
		t.Fatalf("temporaryCertificate() error = %v", err)
	}

	id, err := ariCertID(certPEM)
	if err != nil {
		t.Fatalf("ariCertID() error = %v", err)
	}
	if id == "" {
		t.Fatal("ariCertID() returned empty ID")
	}
}

func testTimePtr(value time.Time) *time.Time {
	return &value
}

func testCertificateConfig(t *testing.T) config.Certificate {
	t.Helper()
	return config.Certificate{
		HTTPListen: ":80",
		CacheDir:   t.TempDir(),
		CADirURL:   config.DefaultCADirURL,
	}
}
