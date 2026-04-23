package web

import (
	"bytes"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/link"
	"github.com/emilmelnikov/xray-easy/internal/users"
	qrcode "github.com/skip2/go-qrcode"
)

var profileTemplate = template.Must(template.New("profile").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Username}}</title>
</head>
<body>
  <h1>{{.Username}}</h1>
  <p><a href="{{.SubscriptionURL}}">Subscription</a></p>
  <img src="{{.QRCodeDataURL}}" alt="Subscription QR code">
  <ul>
  {{range .Links}}
    <li><code>{{.}}</code></li>
  {{end}}
  </ul>
</body>
</html>
`))

type ProfilePage struct {
	Username        string
	SubscriptionURL string
	QRCodeDataURL   string
	Links           []string
}

func NewHandler(cfg *config.Config, file *users.File) (http.Handler, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	switch cfg.Role {
	case config.RoleMain:
		if file == nil {
			return nil, errors.New("users file is nil for main handler")
		}
		return newMainHandler(cfg, file), nil
	case config.RoleOut:
		return landingHandler(), nil
	default:
		return nil, errors.New("unsupported config role")
	}
}

func landingHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body><h1>xray-easy</h1></body></html>"))
	})
	return mux
}

func newMainHandler(cfg *config.Config, file *users.File) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", landingHandler())
	mux.HandleFunc("/profile/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/profile/")
		if token == "" || strings.Contains(token, "/") {
			http.NotFound(w, r)
			return
		}

		user, ok := file.FindByToken(token)
		if !ok {
			http.NotFound(w, r)
			return
		}

		subURL, err := link.SubscriptionURL(cfg, user.Token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		links, err := link.UserLinks(cfg, user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		qrDataURL, err := qrCodeDataURL(subURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var body bytes.Buffer
		if err := profileTemplate.Execute(&body, ProfilePage{
			Username:        user.Username,
			SubscriptionURL: subURL,
			QRCodeDataURL:   qrDataURL,
			Links:           links,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(body.Bytes())
	})
	mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/sub/")
		if token == "" || strings.Contains(token, "/") {
			http.NotFound(w, r)
			return
		}

		user, ok := file.FindByToken(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		links, err := link.UserLinks(cfg, user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var body strings.Builder
		body.WriteString("#profile-title: ")
		body.WriteString(user.Username)
		body.WriteString("\n")
		for i, item := range links {
			if i > 0 {
				body.WriteString("\n")
			}
			body.WriteString(item)
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(body.String()))
	})
	return mux
}

func qrCodeDataURL(value string) (string, error) {
	png, err := qrcode.Encode(value, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
