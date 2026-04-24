package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/link"
	"github.com/emilmelnikov/xray-easy/internal/runtime"
	"github.com/emilmelnikov/xray-easy/internal/secret"
	"github.com/emilmelnikov/xray-easy/internal/users"
	"github.com/emilmelnikov/xray-easy/internal/uuidroute"
)

func Run(args []string, stdout io.Writer, stderr io.Writer) error {
	return run(args, stdout, stderr, rand.Reader)
}

func run(args []string, stdout io.Writer, stderr io.Writer, entropy io.Reader) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing command")
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:], stderr)
	case "init-config":
		return runInitConfig(args[1:], entropy)
	case "add-user":
		return runAddUser(args[1:], stdout, entropy)
	case "add-route":
		return runAddRoute(args[1:], stdout, entropy)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runServe(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", "config.json", "config file path")
	usersPath := fs.String("users", "", "users file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	var userFile *users.File
	if cfg.Role == config.RoleMain {
		path := chooseUsersPath(*usersPath, *configPath)
		userFile, err = users.Load(path)
		if err != nil {
			return err
		}
		if err := userFile.Validate(cfg); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runtime.Serve(ctx, cfg, userFile)
}

func runInitConfig(args []string, entropy io.Reader) error {
	fs := flag.NewFlagSet("init-config", flag.ContinueOnError)

	outputPath := fs.String("output", "config.json", "main config output path")
	usersPath := fs.String("users-output", "", "users output path")
	listen := fs.String("listen", ":443", "public vless listen address")
	serverName := fs.String("server-name", "", "public hostname and reality server name")
	httpListen := fs.String("http-listen", config.DefaultHTTPListen, "local http listen address")
	certCache := fs.String("cert-cache", config.DefaultCertCache, "certificate cache directory")
	caDirURL := fs.String("ca-dir-url", config.DefaultCADirURL, "ACME directory URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverName == "" {
		return errors.New("-server-name is required")
	}

	privateKey, _, err := secret.GenerateX25519(entropy)
	if err != nil {
		return err
	}
	shortID, err := secret.GenerateShortID(entropy)
	if err != nil {
		return err
	}
	routeID, err := secret.GenerateRouteID(nil, entropy)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		Role:       config.RoleMain,
		HTTPListen: *httpListen,
		Certificate: config.Certificate{
			CacheDir: *certCache,
			CADirURL: *caDirURL,
		},
		Inbound: config.Inbound{
			Listen:     *listen,
			ServerName: *serverName,
			PrivateKey: privateKey,
			ShortID:    shortID,
		},
		Routes: []config.RouteEntry{
			{
				ID:    routeID,
				Name:  "local",
				Title: "local",
				Outbound: config.Outbound{
					Type: config.OutboundTypeFreedom,
				},
			},
		},
	}
	if err := config.Save(*outputPath, cfg); err != nil {
		return err
	}

	usersFile := &users.File{Users: []users.User{}}
	if err := users.Save(chooseUsersOutputPath(*usersPath, *outputPath), usersFile); err != nil {
		return err
	}
	return nil
}

func runAddUser(args []string, stdout io.Writer, entropy io.Reader) error {
	fs := flag.NewFlagSet("add-user", flag.ContinueOnError)

	configPath := fs.String("config", "config.json", "config file path")
	usersPath := fs.String("users", "", "users file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: xray-easy add-user -config config.json -users users.json <username>")
	}
	username := strings.TrimSpace(fs.Arg(0))
	if username == "" {
		return errors.New("username must not be empty")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Role != config.RoleMain {
		return errors.New("add-user requires a main config")
	}

	userPath := chooseUsersPath(*usersPath, *configPath)
	file, err := users.Load(userPath)
	if err != nil {
		return err
	}
	if err := file.Validate(cfg); err != nil {
		return err
	}

	for _, existing := range file.Users {
		if existing.Username == username {
			return fmt.Errorf("user %q already exists", username)
		}
	}

	token, err := secret.GenerateToken(entropy)
	if err != nil {
		return err
	}
	newUser := users.User{
		Username: username,
		Token:    token,
		Clients:  make([]users.Client, 0, len(cfg.Routes)),
	}
	for _, route := range cfg.Routes {
		uuid, err := uuidroute.Generate(route.ID, entropy)
		if err != nil {
			return err
		}
		newUser.Clients = append(newUser.Clients, users.Client{
			Route: route.Name,
			UUID:  uuid,
		})
	}

	file.Users = append(file.Users, newUser)
	if err := users.Save(userPath, file); err != nil {
		return err
	}

	url, err := link.ProfileURL(cfg, token)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, url)
	return err
}

func runAddRoute(args []string, stdout io.Writer, entropy io.Reader) error {
	fs := flag.NewFlagSet("add-route", flag.ContinueOnError)

	configPath := fs.String("config", "config.json", "config file path")
	usersPath := fs.String("users", "", "users file path")
	address := fs.String("address", "", "relay node address for the main node")
	port := fs.Int("port", 0, "relay node port for the main node")
	title := fs.String("title", "", "route title")
	listen := fs.String("listen", ":443", "out node public vless listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: xray-easy add-route -config config.json -users users.json <route-name> -address relay.example.com -port 443")
	}

	routeName := strings.TrimSpace(fs.Arg(0))
	if routeName == "" {
		return errors.New("route name must not be empty")
	}
	if *address == "" {
		return errors.New("-address is required")
	}
	if *port < 1 || *port > 65535 {
		return errors.New("-port must be between 1 and 65535")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Role != config.RoleMain {
		return errors.New("add-route requires a main config")
	}

	userPath := chooseUsersPath(*usersPath, *configPath)
	file, err := users.Load(userPath)
	if err != nil {
		return err
	}
	if err := file.Validate(cfg); err != nil {
		return err
	}
	if _, ok := cfg.RouteByName(routeName); ok {
		return fmt.Errorf("route %q already exists", routeName)
	}
	mainDest, err := cfg.PublicInboundAddress()
	if err != nil {
		return err
	}

	routeID, err := secret.GenerateRouteID(cfg.RouteIDs(), entropy)
	if err != nil {
		return err
	}
	privateKey, publicKey, err := secret.GenerateX25519(entropy)
	if err != nil {
		return err
	}
	shortID, err := secret.GenerateShortID(entropy)
	if err != nil {
		return err
	}
	relayUUID, err := uuidroute.Generate(routeID, entropy)
	if err != nil {
		return err
	}

	routeTitle := routeName
	if *title != "" {
		routeTitle = *title
	}

	cfg.Routes = append(cfg.Routes, config.RouteEntry{
		ID:    routeID,
		Name:  routeName,
		Title: routeTitle,
		Outbound: config.Outbound{
			Type:       config.OutboundTypeRelay,
			Address:    *address,
			Port:       *port,
			ServerName: cfg.Inbound.ServerName,
			PublicKey:  publicKey,
			ShortID:    shortID,
			UUID:       relayUUID,
		},
	})

	for i := range file.Users {
		uuid, err := uuidroute.Generate(routeID, entropy)
		if err != nil {
			return err
		}
		file.Users[i].Clients = append(file.Users[i].Clients, users.Client{
			Route: routeName,
			UUID:  uuid,
		})
	}

	if err := config.Save(*configPath, cfg); err != nil {
		return err
	}
	if err := users.Save(userPath, file); err != nil {
		return err
	}

	outConfig := &config.Config{
		Role:     config.RoleOut,
		LogLevel: cfg.LogLevel,
		Inbound: config.Inbound{
			Listen:     *listen,
			ServerName: cfg.Inbound.ServerName,
			Dest:       mainDest,
			PrivateKey: privateKey,
			ShortID:    shortID,
			RelayUUID:  relayUUID,
		},
	}
	outConfig.Normalize()
	if err := outConfig.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(outConfig, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = stdout.Write(data)
	return err
}

func chooseUsersPath(usersPath string, configPath string) string {
	if usersPath != "" {
		return usersPath
	}
	return filepath.Join(filepath.Dir(configPath), "users.json")
}

func chooseUsersOutputPath(usersPath string, configPath string) string {
	if usersPath != "" {
		return usersPath
	}
	return filepath.Join(filepath.Dir(configPath), "users.json")
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: xray-easy <command> [flags]")
	_, _ = fmt.Fprintln(w, "commands: serve, init-config, add-user, add-route")
}
