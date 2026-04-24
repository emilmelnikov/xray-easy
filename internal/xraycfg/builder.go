package xraycfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/users"
	"github.com/xtls/xray-core/core"
	xjson "github.com/xtls/xray-core/infra/conf/serial"
)

type rootConfig struct {
	Log       logConfig     `json:"log"`
	Inbounds  []inbound     `json:"inbounds"`
	Outbounds []outbound    `json:"outbounds"`
	Routing   *routingRules `json:"routing,omitempty"`
}

type logConfig struct {
	LogLevel string `json:"loglevel"`
}

type inbound struct {
	Tag            string          `json:"tag,omitempty"`
	Listen         string          `json:"listen,omitempty"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       inboundSettings `json:"settings"`
	StreamSettings streamSettings  `json:"streamSettings"`
}

type inboundSettings struct {
	Clients    []clientSettings `json:"clients"`
	Decryption string           `json:"decryption"`
}

type clientSettings struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`
	Flow  string `json:"flow"`
}

type outbound struct {
	Tag            string          `json:"tag,omitempty"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings,omitempty"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
}

type streamSettings struct {
	Network         string        `json:"network"`
	Security        string        `json:"security"`
	RealitySettings realityConfig `json:"realitySettings"`
}

type realityConfig struct {
	Dest        string   `json:"dest,omitempty"`
	ServerNames []string `json:"serverNames,omitempty"`
	PrivateKey  string   `json:"privateKey,omitempty"`
	ShortIDs    []string `json:"shortIds,omitempty"`

	Fingerprint string `json:"fingerprint,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type routingRules struct {
	Rules []routingRule `json:"rules"`
}

type routingRule struct {
	Type        string `json:"type"`
	VLESSRoute  uint16 `json:"vlessRoute"`
	OutboundTag string `json:"outboundTag"`
}

func Build(cfg *config.Config, file *users.File) (*core.Config, error) {
	jsonConfig, err := BuildJSON(cfg, file)
	if err != nil {
		return nil, err
	}
	return xjson.LoadJSONConfig(bytes.NewReader(jsonConfig))
}

func BuildJSON(cfg *config.Config, file *users.File) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	cfg.Normalize()

	root := rootConfig{
		Log: logConfig{LogLevel: cfg.LogLevel},
	}

	switch cfg.Role {
	case config.RoleMain:
		if file == nil {
			return nil, fmt.Errorf("users file is nil for main config")
		}
		built, err := buildMain(cfg, file)
		if err != nil {
			return nil, err
		}
		root.Inbounds = built.Inbounds
		root.Outbounds = built.Outbounds
		root.Routing = built.Routing
	case config.RoleOut:
		built, err := buildOut(cfg)
		if err != nil {
			return nil, err
		}
		root.Inbounds = built.Inbounds
		root.Outbounds = built.Outbounds
	default:
		return nil, fmt.Errorf("unsupported role %q", cfg.Role)
	}

	return json.Marshal(root)
}

func buildMain(cfg *config.Config, file *users.File) (rootConfig, error) {
	host, port, err := splitListen(cfg.Inbound.Listen)
	if err != nil {
		return rootConfig{}, err
	}
	dest, err := localTarget(cfg.HTTPListenAddr())
	if err != nil {
		return rootConfig{}, err
	}

	clients := make([]clientSettings, 0, len(file.Users)*len(cfg.Routes))
	for _, user := range file.Users {
		for _, client := range user.Clients {
			clients = append(clients, clientSettings{
				ID:    client.UUID,
				Email: clientEmail(user.Username, client.Route),
				Flow:  "xtls-rprx-vision",
			})
		}
	}

	root := rootConfig{
		Inbounds: []inbound{
			{
				Tag:      "public-in",
				Listen:   host,
				Port:     port,
				Protocol: "vless",
				Settings: inboundSettings{
					Clients:    clients,
					Decryption: "none",
				},
				StreamSettings: streamSettings{
					Network:  "tcp",
					Security: "reality",
					RealitySettings: realityConfig{
						Dest:        dest,
						ServerNames: []string{cfg.Inbound.ServerName},
						PrivateKey:  cfg.Inbound.PrivateKey,
						ShortIDs:    []string{cfg.Inbound.ShortID},
					},
				},
			},
		},
		Outbounds: make([]outbound, 0, len(cfg.Routes)),
		Routing: &routingRules{
			Rules: make([]routingRule, 0, len(cfg.Routes)),
		},
	}

	for _, route := range cfg.Routes {
		out, err := routeOutbound(route)
		if err != nil {
			return rootConfig{}, err
		}
		root.Outbounds = append(root.Outbounds, out)
		root.Routing.Rules = append(root.Routing.Rules, routingRule{
			Type:        "field",
			VLESSRoute:  route.ID,
			OutboundTag: route.Name,
		})
	}

	return root, nil
}

func clientEmail(username string, route string) string {
	if route == "" {
		return username
	}
	return username + "@" + route
}

func buildOut(cfg *config.Config) (rootConfig, error) {
	host, port, err := splitListen(cfg.Inbound.Listen)
	if err != nil {
		return rootConfig{}, err
	}

	return rootConfig{
		Inbounds: []inbound{
			{
				Tag:      "relay-in",
				Listen:   host,
				Port:     port,
				Protocol: "vless",
				Settings: inboundSettings{
					Clients: []clientSettings{
						{
							ID:    cfg.Inbound.RelayUUID,
							Email: "relay",
							Flow:  "xtls-rprx-vision",
						},
					},
					Decryption: "none",
				},
				StreamSettings: streamSettings{
					Network:  "tcp",
					Security: "reality",
					RealitySettings: realityConfig{
						Dest:        cfg.Inbound.Dest,
						ServerNames: []string{cfg.Inbound.ServerName},
						PrivateKey:  cfg.Inbound.PrivateKey,
						ShortIDs:    []string{cfg.Inbound.ShortID},
					},
				},
			},
		},
		Outbounds: []outbound{
			{
				Tag:      "direct",
				Protocol: "freedom",
				Settings: json.RawMessage(`{}`),
			},
		},
	}, nil
}

func routeOutbound(route config.RouteEntry) (outbound, error) {
	switch route.Outbound.Type {
	case config.OutboundTypeFreedom:
		return outbound{
			Tag:      route.Name,
			Protocol: "freedom",
			Settings: json.RawMessage(`{}`),
		}, nil
	case config.OutboundTypeRelay:
		settings, err := json.Marshal(map[string]any{
			"vnext": []map[string]any{
				{
					"address": route.Outbound.Address,
					"port":    route.Outbound.Port,
					"users": []map[string]any{
						{
							"id":         route.Outbound.UUID,
							"encryption": "none",
							"flow":       "xtls-rprx-vision",
						},
					},
				},
			},
		})
		if err != nil {
			return outbound{}, err
		}
		return outbound{
			Tag:      route.Name,
			Protocol: "vless",
			Settings: settings,
			StreamSettings: &streamSettings{
				Network:  "tcp",
				Security: "reality",
				RealitySettings: realityConfig{
					Fingerprint: "chrome",
					ServerName:  route.Outbound.ServerName,
					PublicKey:   route.Outbound.PublicKey,
					ShortID:     route.Outbound.ShortID,
					SpiderX:     "/",
				},
			},
		}, nil
	default:
		return outbound{}, fmt.Errorf("unsupported outbound type %q", route.Outbound.Type)
	}
}

func localTarget(value string) (string, error) {
	host, port, err := splitListen(value)
	if err != nil {
		return "", err
	}
	if host == "" {
		return fmt.Sprintf("localhost:%d", port), nil
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func splitListen(value string) (string, int, error) {
	host, portString, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("invalid listen address %q", value)
	}
	port, err := net.LookupPort("tcp", portString)
	if err != nil {
		return "", 0, fmt.Errorf("invalid listen address %q", value)
	}
	return host, port, nil
}
