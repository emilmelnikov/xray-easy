package certmgr

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const (
	renewBefore        = 30 * 24 * time.Hour
	fallbackRenewCheck = 12 * time.Hour
	maxARIWait         = 365 * 24 * time.Hour
)

type Manager struct {
	domain string
	cfg    config.Certificate

	challenges *httpProvider

	mu        sync.RWMutex
	cert      *tls.Certificate
	certPEM   []byte
	keyPEM    []byte
	issuerPEM []byte
	meta      certMeta
}

type certMeta struct {
	Domain        string `json:"domain"`
	CertURL       string `json:"cert_url,omitempty"`
	CertStableURL string `json:"cert_stable_url,omitempty"`
}

type renewalMeta struct {
	CertID               string    `json:"cert_id,omitempty"`
	SuggestedWindowStart time.Time `json:"suggested_window_start,omitempty"`
	SuggestedWindowEnd   time.Time `json:"suggested_window_end,omitempty"`
	RetryAfter           string    `json:"retry_after,omitempty"`
	RenewAt              time.Time `json:"renew_at,omitempty"`
	NextCheck            time.Time `json:"next_check,omitempty"`
	ExplanationURL       string    `json:"explanation_url,omitempty"`
	LastChecked          time.Time `json:"last_checked"`
}

type renewalSchedule struct {
	delay time.Duration
	renew bool
}

type accountUser struct {
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *accountUser) GetEmail() string {
	return ""
}

func (u *accountUser) GetRegistration() *registration.Resource {
	return u.registration
}

func (u *accountUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func New(domain string, cfg config.Certificate) (*Manager, error) {
	if domain == "" {
		return nil, errors.New("certificate domain is required")
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = config.DefaultCertCache
	}
	if cfg.CADirURL == "" {
		cfg.CADirURL = config.DefaultCADirURL
	}
	return &Manager{
		domain:     domain,
		cfg:        cfg,
		challenges: newHTTPProvider(domain),
	}, nil
}

func (m *Manager) LoadOrCreateTemporary() error {
	if err := os.MkdirAll(m.cfg.CacheDir, 0o700); err != nil {
		return fmt.Errorf("create certificate cache: %w", err)
	}

	if err := m.loadCertificate(); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	certPEM, keyPEM, err := temporaryCertificate(m.domain)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	m.setCertificate(&cert, certPEM, keyPEM, nil, certMeta{Domain: m.domain})
	return nil
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, errors.New("certificate is not loaded")
	}
	return m.cert, nil
}

func (m *Manager) HTTPHandler() http.Handler {
	return m.challenges
}

func (m *Manager) Ensure(ctx context.Context) error {
	_ = ctx

	m.mu.RLock()
	hasCert := len(m.certPEM) != 0
	needsCert := needsRenewal(m.certPEM, renewBefore)
	m.mu.RUnlock()
	if hasCert && !needsCert {
		if _, err := m.loadResource(); err == nil {
			return nil
		}
	}

	if !hasCert {
		if err := m.loadCertificate(); err == nil {
			if !needsRenewal(m.currentCertPEM(), renewBefore) {
				return nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return m.Renew(ctx)
}

func (m *Manager) Renew(ctx context.Context) error {
	_ = ctx

	client, err := m.client()
	if err != nil {
		return err
	}

	cached, err := m.loadResource()
	var replacesCertID string
	var res *certificate.Resource
	if err == nil && len(cached.Certificate) != 0 && len(cached.PrivateKey) != 0 {
		replacesCertID, _ = ariCertID(cached.Certificate)
		res, err = m.renewResource(client, cached, replacesCertID)
	} else {
		res, err = client.Certificate.Obtain(certificate.ObtainRequest{
			Domains: []string{m.domain},
			Bundle:  true,
		})
	}
	if err != nil {
		return fmt.Errorf("obtain certificate for %s: %w", m.domain, err)
	}
	if err := m.saveResource(res); err != nil {
		return err
	}
	if err := m.loadCertificate(); err != nil {
		return err
	}
	_ = m.removeRenewalMeta()
	return nil
}

func (m *Manager) RenewLoop(ctx context.Context) {
	for {
		schedule, err := m.nextRenewalSchedule(ctx)
		if err != nil {
			log.Printf("xray-easy: certificate renewal check failed: %v", err)
			schedule = renewalSchedule{delay: fallbackRenewCheck}
		}

		timer := time.NewTimer(schedule.delay)
		select {
		case <-timer.C:
			if !schedule.renew {
				continue
			}
			if err := m.Renew(ctx); err != nil {
				log.Printf("xray-easy: certificate renewal failed: %v", err)
				if !sleepContext(ctx, fallbackRenewCheck) {
					return
				}
			}
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

func (m *Manager) nextRenewalSchedule(ctx context.Context) (renewalSchedule, error) {
	_ = ctx

	now := time.Now().UTC()

	leaf, err := m.currentLeaf()
	if err != nil {
		return renewalSchedule{}, err
	}
	if needsRenewal(m.currentCertPEM(), renewBefore) {
		return renewalSchedule{renew: true}, nil
	}
	if schedule, ok := m.cachedRenewalSchedule(leaf, now); ok {
		return schedule, nil
	}

	client, err := m.client()
	if err != nil {
		return renewalSchedule{}, err
	}

	renewAt, nextCheck, err := m.ariSchedule(client, leaf, now)
	if err != nil {
		if errors.Is(err, api.ErrNoARI) {
			return fallbackRenewSchedule(leaf, now), nil
		}
		return renewalSchedule{delay: fallbackRenewCheck}, err
	}
	return ariRenewalSchedule(renewAt, nextCheck, now), nil
}

func (m *Manager) ariSchedule(client *lego.Client, leaf *x509.Certificate, now time.Time) (*time.Time, time.Time, error) {
	info, err := client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf})
	if err != nil {
		return nil, time.Time{}, err
	}

	renewAt := info.ShouldRenewAt(now, maxARIWait)
	nextCheck := now.Add(info.RetryAfter)
	if info.RetryAfter <= 0 {
		nextCheck = now.Add(fallbackRenewCheck)
	}
	if renewAt != nil && renewAt.Before(nextCheck) {
		nextCheck = *renewAt
	}

	certID, err := certificate.MakeARICertID(leaf)
	if err != nil {
		return nil, time.Time{}, err
	}
	meta := renewalMeta{
		CertID:               certID,
		SuggestedWindowStart: info.SuggestedWindow.Start.UTC(),
		SuggestedWindowEnd:   info.SuggestedWindow.End.UTC(),
		RetryAfter:           info.RetryAfter.String(),
		NextCheck:            nextCheck.UTC(),
		ExplanationURL:       info.ExplanationURL,
		LastChecked:          now.UTC(),
	}
	if renewAt != nil {
		meta.RenewAt = renewAt.UTC()
	}
	if err := m.saveRenewalMeta(meta); err != nil {
		return nil, time.Time{}, err
	}

	return renewAt, nextCheck, nil
}

func (m *Manager) cachedRenewalSchedule(leaf *x509.Certificate, now time.Time) (renewalSchedule, bool) {
	meta, err := m.loadRenewalMeta()
	if err != nil {
		return renewalSchedule{}, false
	}
	certID, err := certificate.MakeARICertID(leaf)
	if err != nil || meta.CertID != certID {
		return renewalSchedule{}, false
	}

	if !meta.RenewAt.IsZero() && !meta.RenewAt.After(now) {
		return renewalSchedule{renew: true}, true
	}
	if meta.NextCheck.After(now) {
		return ariRenewalSchedule(timePtr(meta.RenewAt), meta.NextCheck, now), true
	}
	return renewalSchedule{}, false
}

func (m *Manager) client() (*lego.Client, error) {
	user, err := m.loadOrCreateAccount()
	if err != nil {
		return nil, err
	}

	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = m.cfg.CADirURL

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetHTTP01Provider(m.challenges, http01.SetDelay(2*time.Second)); err != nil {
		return nil, err
	}

	if user.registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, err
		}
		user.registration = reg
		if err := m.saveRegistration(reg); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (m *Manager) renewResource(client *lego.Client, cached certificate.Resource, replacesCertID string) (*certificate.Resource, error) {
	privateKey, err := certcrypto.ParsePEMPrivateKey(cached.PrivateKey)
	if err != nil {
		return nil, err
	}

	domains := []string{m.domain}
	if certs, err := certcrypto.ParsePEMBundle(cached.Certificate); err == nil && len(certs) > 0 {
		if extracted := certcrypto.ExtractDomains(certs[0]); len(extracted) > 0 {
			domains = extracted
		}
	}

	return client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:        domains,
		PrivateKey:     privateKey,
		Bundle:         true,
		ReplacesCertID: replacesCertID,
	})
}

func (m *Manager) loadOrCreateAccount() (*accountUser, error) {
	keyPath := filepath.Join(m.cfg.CacheDir, "account.key")
	keyPEM, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return nil, err
		}
		keyPEM = certcrypto.PEMEncode(key)
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, fmt.Errorf("write account key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("read account key: %w", err)
	}

	key, err := certcrypto.ParsePEMPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}

	user := &accountUser{key: key}
	reg, err := m.loadRegistration()
	if err == nil {
		user.registration = reg
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return user, nil
}

func (m *Manager) loadRegistration() (*registration.Resource, error) {
	data, err := os.ReadFile(filepath.Join(m.cfg.CacheDir, "account.json"))
	if err != nil {
		return nil, err
	}
	var reg registration.Resource
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("decode account registration: %w", err)
	}
	return &reg, nil
}

func (m *Manager) saveRegistration(reg *registration.Resource) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(filepath.Join(m.cfg.CacheDir, "account.json"), data, 0o600)
}

func (m *Manager) loadResource() (certificate.Resource, error) {
	meta, err := m.loadMeta()
	if err != nil {
		return certificate.Resource{}, err
	}
	certPEM, err := os.ReadFile(m.path("crt"))
	if err != nil {
		return certificate.Resource{}, err
	}
	keyPEM, err := os.ReadFile(m.path("key"))
	if err != nil {
		return certificate.Resource{}, err
	}
	issuerPEM, err := os.ReadFile(m.path("issuer.crt"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return certificate.Resource{}, err
	}
	return certificate.Resource{
		Domain:            meta.Domain,
		CertURL:           meta.CertURL,
		CertStableURL:     meta.CertStableURL,
		PrivateKey:        keyPEM,
		Certificate:       certPEM,
		IssuerCertificate: issuerPEM,
	}, nil
}

func (m *Manager) saveResource(res *certificate.Resource) error {
	if res == nil {
		return errors.New("certificate resource is nil")
	}
	if err := os.WriteFile(m.path("crt"), res.Certificate, 0o600); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(m.path("key"), res.PrivateKey, 0o600); err != nil {
		return fmt.Errorf("write certificate key: %w", err)
	}
	if len(res.IssuerCertificate) != 0 {
		if err := os.WriteFile(m.path("issuer.crt"), res.IssuerCertificate, 0o600); err != nil {
			return fmt.Errorf("write issuer certificate: %w", err)
		}
	}
	meta := certMeta{
		Domain:        res.Domain,
		CertURL:       res.CertURL,
		CertStableURL: res.CertStableURL,
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(m.path("json"), data, 0o600); err != nil {
		return fmt.Errorf("write certificate metadata: %w", err)
	}
	return nil
}

func (m *Manager) saveRenewalMeta(meta renewalMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(m.path("ari.json"), data, 0o600)
}

func (m *Manager) loadRenewalMeta() (renewalMeta, error) {
	data, err := os.ReadFile(m.path("ari.json"))
	if err != nil {
		return renewalMeta{}, err
	}
	var meta renewalMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return renewalMeta{}, fmt.Errorf("decode ARI metadata: %w", err)
	}
	return meta, nil
}

func (m *Manager) removeRenewalMeta() error {
	err := os.Remove(m.path("ari.json"))
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (m *Manager) loadCertificate() error {
	res, err := m.loadResource()
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(res.Certificate, res.PrivateKey)
	if err != nil {
		return fmt.Errorf("load certificate key pair: %w", err)
	}
	m.setCertificate(&cert, res.Certificate, res.PrivateKey, res.IssuerCertificate, certMeta{
		Domain:        res.Domain,
		CertURL:       res.CertURL,
		CertStableURL: res.CertStableURL,
	})
	return nil
}

func (m *Manager) loadMeta() (certMeta, error) {
	data, err := os.ReadFile(m.path("json"))
	if err != nil {
		return certMeta{}, err
	}
	var meta certMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return certMeta{}, fmt.Errorf("decode certificate metadata: %w", err)
	}
	return meta, nil
}

func (m *Manager) setCertificate(cert *tls.Certificate, certPEM, keyPEM, issuerPEM []byte, meta certMeta) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cert = cert
	m.certPEM = certPEM
	m.keyPEM = keyPEM
	m.issuerPEM = issuerPEM
	m.meta = meta
}

func (m *Manager) path(ext string) string {
	return filepath.Join(m.cfg.CacheDir, safeName(m.domain)+"."+ext)
}

func safeName(value string) string {
	replacer := strings.NewReplacer("*", "_", "/", "_", "\\", "_", ":", "_")
	return replacer.Replace(value)
}

func needsRenewal(certPEM []byte, threshold time.Duration) bool {
	cert, err := leafCertificate(certPEM)
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) <= threshold
}

func (m *Manager) currentLeaf() (*x509.Certificate, error) {
	return leafCertificate(m.currentCertPEM())
}

func (m *Manager) currentCertPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.certPEM...)
}

func leafCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("certificate PEM did not contain a certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ariCertID(certPEM []byte) (string, error) {
	leaf, err := leafCertificate(certPEM)
	if err != nil {
		return "", err
	}
	return certificate.MakeARICertID(leaf)
}

func fallbackRenewSchedule(cert *x509.Certificate, now time.Time) renewalSchedule {
	renewAt := cert.NotAfter.Add(-renewBefore)
	if !renewAt.After(now) {
		return renewalSchedule{renew: true}
	}
	delay := renewAt.Sub(now)
	if delay > fallbackRenewCheck {
		return renewalSchedule{delay: fallbackRenewCheck}
	}
	return renewalSchedule{delay: delay, renew: true}
}

func ariRenewalSchedule(renewAt *time.Time, nextCheck time.Time, now time.Time) renewalSchedule {
	if renewAt != nil && !renewAt.IsZero() && !renewAt.After(now) {
		return renewalSchedule{renew: true}
	}
	if renewAt != nil && !renewAt.IsZero() && (nextCheck.IsZero() || !renewAt.After(nextCheck)) {
		return renewalSchedule{delay: nonNegativeDelay(renewAt.Sub(now)), renew: true}
	}
	if nextCheck.After(now) {
		return renewalSchedule{delay: nextCheck.Sub(now)}
	}
	return renewalSchedule{delay: fallbackRenewCheck}
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func nonNegativeDelay(delay time.Duration) time.Duration {
	if delay < 0 {
		return 0
	}
	return delay
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func temporaryCertificate(domain string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
