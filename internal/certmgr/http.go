package certmgr

import (
	"net/http"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/challenge/http01"
)

type httpProvider struct {
	domain string

	mu        sync.RWMutex
	responses map[string]string
}

func newHTTPProvider(domain string) *httpProvider {
	return &httpProvider{
		domain:    domain,
		responses: make(map[string]string),
	}
}

func (p *httpProvider) Present(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.responses[token] = keyAuth
	return nil
}

func (p *httpProvider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.responses, token)
	return nil
}

func (p *httpProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, http01.PathPrefix) {
		p.serveChallenge(w, r)
		return
	}

	target := "https://" + p.domain + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

func (p *httpProvider) serveChallenge(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, http01.PathPrefix)

	p.mu.RLock()
	keyAuth, ok := p.responses[token]
	p.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(keyAuth))
}
