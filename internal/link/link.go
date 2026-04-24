package link

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/secret"
	"github.com/emilmelnikov/xray-easy/internal/users"
)

func ProfileURL(cfg *config.Config, token string) (string, error) {
	return absoluteURL(cfg, "/profile/"+token)
}

func SubscriptionURL(cfg *config.Config, token string) (string, error) {
	return absoluteURL(cfg, "/sub/"+token)
}

func UserLinks(cfg *config.Config, user users.User) ([]string, error) {
	publicKey, err := secret.PublicKeyFromPrivate(cfg.Inbound.PrivateKey)
	if err != nil {
		return nil, err
	}

	_, port, err := net.SplitHostPort(cfg.Inbound.Listen)
	if err != nil {
		return nil, fmt.Errorf("invalid inbound listen %q: %w", cfg.Inbound.Listen, err)
	}

	links := make([]string, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		client, ok := user.ClientForRoute(route.Name)
		if !ok {
			return nil, fmt.Errorf("user %q has no client for route %q", user.Username, route.Name)
		}
		u := url.URL{
			Scheme:   "vless",
			User:     url.User(client.UUID),
			Host:     net.JoinHostPort(cfg.Inbound.ServerName, port),
			Path:     "",
			Fragment: route.DisplayTitle(),
		}

		values := url.Values{
			"encryption": []string{"none"},
			"flow":       []string{"xtls-rprx-vision"},
			"fp":         []string{"chrome"},
			"pbk":        []string{publicKey},
			"security":   []string{"reality"},
			"sid":        []string{cfg.Inbound.ShortID},
			"sni":        []string{cfg.Inbound.ServerName},
			"spx":        []string{"/"},
			"type":       []string{"tcp"},
		}
		u.RawQuery = values.Encode()
		links = append(links, u.String())
	}
	return links, nil
}

func absoluteURL(cfg *config.Config, path string) (string, error) {
	port, err := cfg.ListenPort()
	if err != nil {
		return "", err
	}

	host := cfg.Inbound.ServerName
	if port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	}

	return (&url.URL{
		Scheme: "https",
		Host:   host,
		Path:   path,
	}).String(), nil
}
