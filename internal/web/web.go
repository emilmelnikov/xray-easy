package web

import (
	"bytes"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/link"
	"github.com/emilmelnikov/xray-easy/internal/users"
	qrcode "github.com/skip2/go-qrcode"
)

//go:embed templates/*.html
var templateFS embed.FS

var (
	profileTemplate = template.Must(template.New("profile.html").ParseFS(templateFS, "templates/profile.html"))
	authTemplate    = template.Must(template.New("auth.html").ParseFS(templateFS, "templates/auth.html"))
)

type authPage struct {
	Email string
	Error string
}

type ProfilePage struct {
	Username        string
	SubscriptionURL string
	QRCodeDataURL   template.URL
	DeepLinks       []ProfileDeepLink
	Lang            string
	LanguageLinks   []ProfileLanguageLink
	Links           []string
	Text            profileText
}

type ProfileDeepLink struct {
	Name string
	URL  template.URL
}

type ProfileLanguageLink struct {
	Code    string
	Label   string
	URL     string
	Current bool
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
		locale := localeFromRequest(r)

		var body bytes.Buffer
		if err := profileTemplate.Execute(&body, ProfilePage{
			Username:        user.Username,
			SubscriptionURL: subURL,
			QRCodeDataURL:   qrDataURL,
			DeepLinks:       profileDeepLinks(subURL, user.Username),
			Lang:            locale.lang(),
			LanguageLinks:   profileLanguageLinks(r.URL.Path, locale),
			Links:           links,
			Text:            locale.profile(),
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
		profileURL, err := link.ProfileURL(cfg, user.Token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var body strings.Builder
		body.WriteString("#profile-update-interval: ")
		body.WriteString(strconv.Itoa(profileUpdateInterval(cfg)))
		body.WriteString("\n")
		body.WriteString("#profile-title: ")
		body.WriteString(subscriptionTitle(cfg))
		body.WriteString("\n#profile-web-page-url: ")
		body.WriteString(profileURL)
		for _, item := range links {
			body.WriteString("\n")
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

func subscriptionTitle(cfg *config.Config) string {
	if cfg.SubscriptionTitle != "" {
		return cfg.SubscriptionTitle
	}
	return cfg.Inbound.ServerName
}

func profileUpdateInterval(cfg *config.Config) int {
	if cfg.ProfileUpdateInterval > 0 {
		return cfg.ProfileUpdateInterval
	}
	return config.DefaultProfileUpdate
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

func qrCodeDataURL(value string) (template.URL, error) {
	png, err := qrcode.Encode(value, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), nil
}

func profileDeepLinks(subURL, name string) []ProfileDeepLink {
	querySub := url.QueryEscape(subURL)
	queryName := url.QueryEscape(name)
	pathSub := url.PathEscape(subURL)
	fragmentName := url.PathEscape(name)

	return []ProfileDeepLink{
		{Name: "Streisand", URL: template.URL("streisand://import/" + pathSub + "#" + fragmentName)},
		{Name: "Karing", URL: template.URL("karing://install-config?url=" + querySub + "&name=" + queryName)},
		{Name: "FoxRay", URL: template.URL("foxray://yiguo.dev/sub/add/?url=" + querySub + "#" + fragmentName)},
		{Name: "V2box", URL: template.URL("v2box://install-sub?url=" + querySub + "&name=" + queryName)},
		{Name: "SingBox", URL: template.URL("sing-box://import-remote-profile?url=" + querySub + "#" + fragmentName)},
		{Name: "ShadowRocket", URL: template.URL("sub://" + pathSub)},
		{Name: "NekoRay", URL: template.URL("sn://subscription?url=" + querySub + "&name=" + queryName)},
		{Name: "V2rayNG", URL: template.URL("v2rayng://install-sub/?url=" + querySub + "%23" + queryName)},
		{Name: "ClashX", URL: template.URL("clashx://install-config?url=" + querySub)},
		{Name: "Clash", URL: template.URL("clash://install-config?url=" + querySub)},
		{Name: "FlClash", URL: template.URL("flclash://install-config?url=" + querySub)},
		{Name: "Hiddify", URL: template.URL("hiddify://install-config/?url=" + querySub)},
		{Name: "Happ", URL: template.URL("happ://add/" + pathSub)},
	}
}

func profileLanguageLinks(path string, current locale) []ProfileLanguageLink {
	return []ProfileLanguageLink{
		{
			Code:    "en",
			Label:   localeEN.profile().English,
			URL:     path + "?lang=en",
			Current: current == localeEN,
		},
		{
			Code:    "ru",
			Label:   localeRU.profile().Russian,
			URL:     path + "?lang=ru",
			Current: current == localeRU,
		},
	}
}
