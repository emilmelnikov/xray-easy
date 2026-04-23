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

var authTemplate = template.Must(template.New("auth").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #f5f7fb;
      color: #172033;
      font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(100% - 32px, 380px);
      padding: 32px;
      border: 1px solid #d9e0ec;
      border-radius: 8px;
      background: #fff;
      box-shadow: 0 20px 50px rgb(23 32 51 / 10%);
    }
    h1 {
      margin: 0 0 8px;
      font-size: 24px;
      line-height: 1.2;
    }
    p {
      margin: 0 0 24px;
      color: #66738a;
    }
    label {
      display: block;
      margin: 16px 0 6px;
      font-size: 14px;
      font-weight: 600;
    }
    input[type="email"],
    input[type="password"] {
      box-sizing: border-box;
      width: 100%;
      height: 44px;
      border: 1px solid #b9c3d3;
      border-radius: 6px;
      padding: 0 12px;
      font: inherit;
    }
    .row {
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 18px 0 22px;
      color: #47546a;
      font-size: 14px;
    }
    button {
      width: 100%;
      height: 44px;
      border: 0;
      border-radius: 6px;
      background: #1f4f8f;
      color: #fff;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }
    .error {
      margin: 0 0 16px;
      padding: 10px 12px;
      border-radius: 6px;
      background: #fff1f1;
      color: #a32222;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <main>
    <h1>Sign in</h1>
    <p>Use your account credentials to continue.</p>
    {{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
    <form method="post" action="/auth">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="username" value="{{.Email}}" required autofocus>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <label class="row">
        <input name="remember" type="checkbox" value="1">
        <span>Remember this device</span>
      </label>
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>
`))

type ProfilePage struct {
	Username        string
	SubscriptionURL string
	QRCodeDataURL   string
	Links           []string
}

type authPage struct {
	Email string
	Error string
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
		return newAuthFallbackHandler(), nil
	default:
		return nil, errors.New("unsupported config role")
	}
}

func newAuthFallbackHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", authHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		redirectToAuth(w, r)
	})
	return mux
}

func newMainHandler(cfg *config.Config, file *users.File) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", authHandler)
	mux.HandleFunc("/profile/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/profile/")
		if token == "" || strings.Contains(token, "/") {
			redirectToAuth(w, r)
			return
		}

		user, ok := file.FindByToken(token)
		if !ok {
			redirectToAuth(w, r)
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
			redirectToAuth(w, r)
			return
		}

		user, ok := file.FindByToken(token)
		if !ok {
			redirectToAuth(w, r)
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		redirectToAuth(w, r)
	})
	return mux
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderAuth(w, authPage{})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		renderAuth(w, authPage{
			Email: strings.TrimSpace(r.Form.Get("email")),
			Error: "Invalid email or password.",
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func renderAuth(w http.ResponseWriter, page authPage) {
	var body bytes.Buffer
	if err := authTemplate.Execute(&body, page); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body.Bytes())
}

func redirectToAuth(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/auth", http.StatusFound)
}

func qrCodeDataURL(value string) (string, error) {
	png, err := qrcode.Encode(value, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
