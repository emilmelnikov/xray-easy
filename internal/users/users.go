package users

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/uuidroute"
)

type File struct {
	Users []User `json:"users"`
}

type User struct {
	Username string   `json:"username"`
	Token    string   `json:"token"`
	Clients  []Client `json:"clients"`
}

type Client struct {
	Route string `json:"route"`
	UUID  string `json:"uuid"`
}

func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read users %q: %w", path, err)
	}

	var file File
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode users %q: %w", path, err)
	}
	return &file, nil
}

func Save(path string, file *File) error {
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("encode users: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for users %q: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write users %q: %w", path, err)
	}
	return nil
}

func (f *File) Validate(cfg *config.Config) error {
	if f == nil {
		return errors.New("users file is nil")
	}
	if cfg == nil {
		return errors.New("config is nil")
	}
	if cfg.Role != config.RoleMain {
		return nil
	}

	usernames := make(map[string]struct{}, len(f.Users))
	tokens := make(map[string]struct{}, len(f.Users))
	routeIDs := make(map[string]uint16, len(cfg.Routes))
	for _, route := range cfg.Routes {
		routeIDs[route.Name] = route.ID
	}

	for _, user := range f.Users {
		if user.Username == "" {
			return errors.New("user username is required")
		}
		if _, ok := usernames[user.Username]; ok {
			return fmt.Errorf("duplicate username %q", user.Username)
		}
		usernames[user.Username] = struct{}{}
		if user.Token == "" {
			return fmt.Errorf("user %q token is required", user.Username)
		}
		if _, ok := tokens[user.Token]; ok {
			return fmt.Errorf("duplicate token %q", user.Token)
		}
		tokens[user.Token] = struct{}{}
		if len(user.Clients) != len(cfg.Routes) {
			return fmt.Errorf("user %q must have exactly %d clients", user.Username, len(cfg.Routes))
		}

		seenRoutes := make(map[string]struct{}, len(user.Clients))
		for _, client := range user.Clients {
			if client.Route == "" {
				return fmt.Errorf("user %q has client with empty route", user.Username)
			}
			routeID, ok := routeIDs[client.Route]
			if !ok {
				return fmt.Errorf("user %q references unknown route %q", user.Username, client.Route)
			}
			if _, ok := seenRoutes[client.Route]; ok {
				return fmt.Errorf("user %q has duplicate client for route %q", user.Username, client.Route)
			}
			seenRoutes[client.Route] = struct{}{}

			uuidRouteID, err := uuidroute.ExtractRouteID(client.UUID)
			if err != nil {
				return fmt.Errorf("user %q has invalid uuid %q: %w", user.Username, client.UUID, err)
			}
			if uuidRouteID != routeID {
				return fmt.Errorf("user %q route %q uuid does not embed route id %d", user.Username, client.Route, routeID)
			}
		}
	}

	return nil
}

func (f *File) FindByToken(token string) (User, bool) {
	for _, user := range f.Users {
		if user.Token == token {
			return user, true
		}
	}
	return User{}, false
}

func (u User) ClientForRoute(name string) (Client, bool) {
	for _, client := range u.Clients {
		if client.Route == name {
			return client, true
		}
	}
	return Client{}, false
}
