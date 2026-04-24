package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/emilmelnikov/xray-easy/internal/certmgr"
	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/users"
	"github.com/emilmelnikov/xray-easy/internal/web"
	"github.com/emilmelnikov/xray-easy/internal/xraycfg"
)

type closer interface {
	Start() error
	Close() error
}

const (
	serverReadTimeout  = 60 * time.Second
	serverWriteTimeout = 60 * time.Second
	serverIdleTimeout  = 120 * time.Second
	hstsHeaderValue    = "max-age=63072000; includeSubDomains"
)

func Serve(ctx context.Context, cfg *config.Config, file *users.File) error {
	switch cfg.Role {
	case config.RoleMain:
		return serveMain(ctx, cfg, file)
	case config.RoleOut:
		return serveOut(ctx, cfg)
	default:
		return fmt.Errorf("unsupported role %q", cfg.Role)
	}
}

func serveMain(ctx context.Context, cfg *config.Config, file *users.File) error {
	handler, err := web.NewHandler(cfg, file)
	if err != nil {
		return err
	}

	certs, err := certmgr.New(cfg.Inbound.ServerName, cfg.Certificate)
	if err != nil {
		return err
	}

	challengeServer := &http.Server{
		Addr:         cfg.Certificate.HTTPListen,
		Handler:      certs.HTTPHandler(),
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
	}

	challengeListener, err := net.Listen("tcp", cfg.Certificate.HTTPListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Certificate.HTTPListen, err)
	}
	challengeErr := serveHTTP(challengeServer, challengeListener)

	if err := certs.Ensure(ctx); err != nil {
		_ = challengeServer.Close()
		return err
	}

	httpServer := &http.Server{
		Addr:         cfg.HTTPListenAddr(),
		Handler:      hstsHandler(handler),
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
			NextProtos:     []string{"h2", "http/1.1"},
			GetCertificate: certs.GetCertificate,
		},
	}
	listener, err := net.Listen("tcp", cfg.HTTPListenAddr())
	if err != nil {
		_ = challengeServer.Close()
		return fmt.Errorf("listen on %s: %w", cfg.HTTPListenAddr(), err)
	}
	tlsListener := tls.NewListener(listener, httpServer.TLSConfig)
	httpErr := serveHTTP(httpServer, tlsListener)

	instance, err := startXray(cfg, file)
	if err != nil {
		_ = httpServer.Close()
		_ = challengeServer.Close()
		return err
	}
	go certs.RenewLoop(ctx)

	select {
	case err := <-httpErr:
		_ = challengeServer.Close()
		_ = instance.Close()
		return err
	case err := <-challengeErr:
		_ = httpServer.Close()
		_ = instance.Close()
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		httpShutdownErr := httpServer.Shutdown(shutdownCtx)
		challengeShutdownErr := challengeServer.Shutdown(shutdownCtx)
		xrayCloseErr := instance.Close()

		if httpShutdownErr != nil {
			return httpShutdownErr
		}
		if challengeShutdownErr != nil {
			return challengeShutdownErr
		}
		if xrayCloseErr != nil {
			return xrayCloseErr
		}
		return nil
	}
}

func serveHTTP(server *http.Server, listener net.Listener) <-chan error {
	errc := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()
	return errc
}

func hstsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", hstsHeaderValue)
		next.ServeHTTP(w, r)
	})
}

func serveOut(ctx context.Context, cfg *config.Config) error {
	instance, err := startXray(cfg, nil)
	if err != nil {
		return err
	}

	<-ctx.Done()
	return instance.Close()
}

func startXray(cfg *config.Config, file *users.File) (closer, error) {
	xrayConfig, err := xraycfg.Build(cfg, file)
	if err != nil {
		return nil, err
	}
	instance, err := newInstance(xrayConfig)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, fmt.Errorf("start xray: %w", err)
	}
	return instance, nil
}
