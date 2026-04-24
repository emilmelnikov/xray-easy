package config

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/emilmelnikov/xray-easy/internal/uuidroute"
)

const (
	RoleMain = "main"
	RoleOut  = "out"

	OutboundTypeFreedom = "freedom"
	OutboundTypeRelay   = "relay"

	DefaultHTTPListen = "127.0.0.1:8080"
	DefaultCertCache  = "certs"
	DefaultCADirURL   = "https://acme-v02.api.letsencrypt.org/directory"
	DefaultLogLevel   = "warning"
)

type Config struct {
	Role        string       `json:"role"`
	HTTPListen  string       `json:"http_listen,omitempty"`
	LogLevel    string       `json:"loglevel,omitempty"`
	Certificate Certificate  `json:"certificate,omitempty"`
	Inbound     Inbound      `json:"inbound"`
	Routes      []RouteEntry `json:"routes,omitempty"`
}

type Certificate struct {
	CacheDir string `json:"cache_dir,omitempty"`
	CADirURL string `json:"ca_dir_url,omitempty"`
}

type Inbound struct {
	Listen     string `json:"listen"`
	ServerName string `json:"server_name"`
	Dest       string `json:"dest,omitempty"`
	PrivateKey string `json:"private_key"`
	ShortID    string `json:"short_id"`
	RelayUUID  string `json:"relay_uuid,omitempty"`
}

type RouteEntry struct {
	ID       uint16   `json:"id"`
	Name     string   `json:"name"`
	Title    string   `json:"title,omitempty"`
	Outbound Outbound `json:"outbound"`
}

type Outbound struct {
	Type       string `json:"type"`
	Address    string `json:"address,omitempty"`
	Port       int    `json:"port,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	ShortID    string `json:"short_id,omitempty"`
	UUID       string `json:"uuid,omitempty"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}

	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func Save(path string, cfg *Config) error {
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for config %q: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config %q: %w", path, err)
	}
	return nil
}

func (c *Config) Normalize() {
	if c.Role != RoleOut && c.HTTPListen == "" {
		c.HTTPListen = DefaultHTTPListen
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	if c.Role != RoleOut && c.Certificate.CacheDir == "" {
		c.Certificate.CacheDir = DefaultCertCache
	}
	if c.Role != RoleOut && c.Certificate.CADirURL == "" {
		c.Certificate.CADirURL = DefaultCADirURL
	}
	for i := range c.Routes {
		if c.Routes[i].Title == "" {
			c.Routes[i].Title = c.Routes[i].Name
		}
	}
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	c.Normalize()
	if c.Role != RoleMain && c.Role != RoleOut {
		return fmt.Errorf("invalid config role %q", c.Role)
	}
	if err := validateLogLevel(c.LogLevel); err != nil {
		return err
	}
	if err := c.Inbound.validate(c.Role); err != nil {
		return err
	}

	switch c.Role {
	case RoleMain:
		if err := validateListen(c.HTTPListen, "http_listen"); err != nil {
			return err
		}
		if err := c.Certificate.validate(); err != nil {
			return err
		}
		if len(c.Routes) == 0 {
			return errors.New("main config requires at least one route")
		}
		ids := make(map[uint16]struct{}, len(c.Routes))
		names := make(map[string]struct{}, len(c.Routes))
		for i, route := range c.Routes {
			if route.ID == 0 {
				return fmt.Errorf("route %q has invalid id 0", route.Name)
			}
			if route.Name == "" {
				return fmt.Errorf("route %d has empty name", i)
			}
			if _, ok := ids[route.ID]; ok {
				return fmt.Errorf("duplicate route id %d", route.ID)
			}
			if _, ok := names[route.Name]; ok {
				return fmt.Errorf("duplicate route name %q", route.Name)
			}
			ids[route.ID] = struct{}{}
			names[route.Name] = struct{}{}
			if err := route.Outbound.validate(route.Name); err != nil {
				return fmt.Errorf("route %q: %w", route.Name, err)
			}
		}
	case RoleOut:
		if len(c.Routes) != 0 {
			return errors.New("out config must not define routes")
		}
		if c.Inbound.RelayUUID == "" {
			return errors.New("out config inbound.relay_uuid is required")
		}
		if _, err := uuidroute.Parse(c.Inbound.RelayUUID); err != nil {
			return fmt.Errorf("out config inbound.relay_uuid is invalid: %w", err)
		}
	}

	return nil
}

func (c Certificate) validate() error {
	if c.CacheDir == "" {
		return errors.New("certificate.cache_dir is required")
	}
	if c.CADirURL == "" {
		return errors.New("certificate.ca_dir_url is required")
	}
	return nil
}

func (i Inbound) validate(role string) error {
	if err := validateListen(i.Listen, "inbound.listen"); err != nil {
		return err
	}
	if i.ServerName == "" {
		return errors.New("inbound.server_name is required")
	}
	if role == RoleOut {
		if i.Dest == "" {
			return errors.New("out config inbound.dest is required")
		}
		if err := validateAddress(i.Dest, "inbound.dest"); err != nil {
			return err
		}
	}
	if err := validateBase64Key(i.PrivateKey, 32, "inbound.private_key"); err != nil {
		return err
	}
	if err := validateShortID(i.ShortID, "inbound.short_id"); err != nil {
		return err
	}
	if role == RoleMain {
		if i.Dest != "" {
			return errors.New("main config inbound.dest must be empty")
		}
		if i.RelayUUID != "" {
			return errors.New("main config inbound.relay_uuid must be empty")
		}
	}
	return nil
}

func (o Outbound) validate(routeName string) error {
	switch o.Type {
	case OutboundTypeFreedom:
		return nil
	case OutboundTypeRelay:
		if o.Address == "" {
			return errors.New("relay outbound.address is required")
		}
		if o.Port < 1 || o.Port > 65535 {
			return fmt.Errorf("relay outbound.port %d is invalid", o.Port)
		}
		if o.ServerName == "" {
			return errors.New("relay outbound.server_name is required")
		}
		if err := validateBase64Key(o.PublicKey, 32, "relay outbound.public_key"); err != nil {
			return err
		}
		if err := validateShortID(o.ShortID, "relay outbound.short_id"); err != nil {
			return err
		}
		if o.UUID == "" {
			return fmt.Errorf("relay outbound.uuid for route %q is required", routeName)
		}
		if _, err := uuidroute.Parse(o.UUID); err != nil {
			return fmt.Errorf("relay outbound.uuid for route %q is invalid: %w", routeName, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported outbound type %q", o.Type)
	}
}

func (r RouteEntry) DisplayTitle() string {
	if r.Title != "" {
		return r.Title
	}
	return r.Name
}

func (c *Config) RouteByName(name string) (RouteEntry, bool) {
	for _, route := range c.Routes {
		if route.Name == name {
			return route, true
		}
	}
	return RouteEntry{}, false
}

func (c *Config) RouteIDs() map[uint16]struct{} {
	ids := make(map[uint16]struct{}, len(c.Routes))
	for _, route := range c.Routes {
		ids[route.ID] = struct{}{}
	}
	return ids
}

func (c *Config) ListenPort() (int, error) {
	_, port, err := splitHostPort(c.Inbound.Listen)
	return port, err
}

func (c *Config) PublicInboundAddress() (string, error) {
	port, err := c.ListenPort()
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(c.Inbound.ServerName, strconv.Itoa(port)), nil
}

func (c *Config) HTTPListenAddr() string {
	if c.HTTPListen == "" {
		return DefaultHTTPListen
	}
	return c.HTTPListen
}

func validateListen(value, field string) error {
	_, _, err := splitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func validateAddress(value, field string) error {
	host, _, err := splitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if host == "" {
		return fmt.Errorf("%s: host is required", field)
	}
	return nil
}

func splitHostPort(value string) (string, int, error) {
	host, portString, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("invalid listen address %q", value)
	}
	port, err := net.LookupPort("tcp", portString)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid listen address %q", value)
	}
	return host, port, nil
}

func validateBase64Key(value string, expectedLen int, field string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != expectedLen {
		return fmt.Errorf("%s is invalid", field)
	}
	return nil
}

func validateShortID(value, field string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > 16 || len(value)%2 != 0 {
		return fmt.Errorf("%s is invalid", field)
	}
	if _, err := hex.DecodeString(strings.ToLower(value)); err != nil {
		return fmt.Errorf("%s is invalid", field)
	}
	return nil
}

func validateLogLevel(value string) error {
	switch value {
	case "debug", "info", "warning", "error", "none":
		return nil
	default:
		return fmt.Errorf("loglevel %q is invalid", value)
	}
}
