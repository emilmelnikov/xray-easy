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
	if err := certs.LoadOrCreateTemporary(); err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:      cfg.HTTPListenAddr(),
		Handler:   handler,
		TLSConfig: certs.TLSConfig(),
	}
	listener, err := net.Listen("tcp", cfg.HTTPListenAddr())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.HTTPListenAddr(), err)
	}
	tlsListener := tls.NewListener(listener, httpServer.TLSConfig)

	httpErr := make(chan error, 1)
	go func() {
		err := httpServer.Serve(tlsListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErr <- err
			return
		}
		httpErr <- nil
	}()

	instance, err := startXray(cfg, file)
	if err != nil {
		_ = httpServer.Close()
		return err
	}
	if err := certs.Ensure(ctx); err != nil {
		_ = httpServer.Close()
		_ = instance.Close()
		return err
	}
	go certs.RenewLoop(ctx)

	select {
	case err := <-httpErr:
		_ = instance.Close()
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		httpShutdownErr := httpServer.Shutdown(shutdownCtx)
		xrayCloseErr := instance.Close()

		if httpShutdownErr != nil {
			return httpShutdownErr
		}
		if xrayCloseErr != nil {
			return xrayCloseErr
		}
		return nil
	}
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
