package certmgr

import (
	"crypto/tls"
	"sync"

	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
)

type alpnProvider struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

func newALPNProvider() *alpnProvider {
	return &alpnProvider{certs: make(map[string]*tls.Certificate)}
}

func (p *alpnProvider) Present(domain, token, keyAuth string) error {
	cert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.certs[domain] = cert
	return nil
}

func (p *alpnProvider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.certs, domain)
	return nil
}

func (p *alpnProvider) Get(domain string) *tls.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.certs[domain]
}
