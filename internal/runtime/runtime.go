package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

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
	handler, err := web.NewHandler(cfg, file)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:    cfg.HTTPListenAddr(),
		Handler: handler,
	}
	listener, err := net.Listen("tcp", cfg.HTTPListenAddr())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.HTTPListenAddr(), err)
	}

	httpErr := make(chan error, 1)
	go func() {
		err := httpServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErr <- err
			return
		}
		httpErr <- nil
	}()

	xrayConfig, err := xraycfg.Build(cfg, file)
	if err != nil {
		_ = httpServer.Close()
		return err
	}
	instance, err := newInstance(xrayConfig)
	if err != nil {
		_ = httpServer.Close()
		return err
	}
	if err := instance.Start(); err != nil {
		_ = httpServer.Close()
		_ = instance.Close()
		return fmt.Errorf("start xray: %w", err)
	}

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
