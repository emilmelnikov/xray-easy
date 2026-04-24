package web

import (
	"net/http"
	"strings"
)

type locale string

const (
	localeEN locale = "en"
	localeRU locale = "ru"
)

type profileText struct {
	Language             string
	English              string
	Russian              string
	PrivateAccessProfile string
	Lede                 string
	QRCodeAria           string
	QRCodeAlt            string
	QRCaption            string
	SubscriptionTitle    string
	SubscriptionHint     string
	Open                 string
	SubscriptionURLAria  string
	CopyURL              string
	OpenInProxyClient    string
	LinksTitle           string
	LinksHint            string
	ConnectionLinkAria   string
	Copy                 string
	Copied               string
	FooterNote           string
}

func localeFromLang(value string) (locale, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "en":
		return localeEN, true
	case "ru":
		return localeRU, true
	default:
		return "", false
	}
}

func localeFromRequest(r *http.Request) locale {
	if lang, ok := localeFromLang(r.URL.Query().Get("lang")); ok {
		return lang
	}
	header := r.Header.Get("Accept-Language")
	for _, item := range strings.Split(header, ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.Split(item, ";")[0]))
		if tag == "ru" || strings.HasPrefix(tag, "ru-") {
			return localeRU
		}
		if tag == "en" || strings.HasPrefix(tag, "en-") {
			return localeEN
		}
	}
	return localeEN
}

func (l locale) lang() string {
	switch l {
	case localeRU:
		return "ru"
	default:
		return "en"
	}
}

func (l locale) profile() profileText {
	switch l {
	case localeRU:
		return profileText{
			Language:             "Язык",
			English:              "English",
			Russian:              "Русский",
			PrivateAccessProfile: "Личный профиль доступа",
			Lede:                 "Отсканируйте код или скопируйте ссылку на подписку в клиентское приложение. Отдельные ссылки подключения доступны ниже для ручного импорта.",
			QRCodeAria:           "QR-код подписки",
			QRCodeAlt:            "QR-код подписки",
			QRCaption:            "Этот QR-код содержит ссылку на подписку для этого профиля.",
			SubscriptionTitle:    "Подписка",
			SubscriptionHint:     "Лучший вариант для клиентских приложений с поддержкой подписок.",
			Open:                 "Открыть",
			SubscriptionURLAria:  "Ссылка на подписку",
			CopyURL:              "Скопировать ссылку",
			OpenInProxyClient:    "Открыть в proxy-клиенте",
			LinksTitle:           "Ссылки подключения",
			LinksHint:            "Используйте их, если нужно вручную импортировать отдельный маршрут.",
			ConnectionLinkAria:   "Ссылка подключения",
			Copy:                 "Скопировать",
			Copied:               "Скопировано",
			FooterNote:           "Храните URL этой страницы в секрете. Любой человек с токеном сможет прочитать этот профиль.",
		}
	default:
		return profileText{
			Language:             "Language",
			English:              "English",
			Russian:              "Russian",
			PrivateAccessProfile: "Private access profile",
			Lede:                 "Scan the code or copy the subscription URL into your client app. Individual connection links are available below for manual import.",
			QRCodeAria:           "Subscription QR code",
			QRCodeAlt:            "Subscription QR code",
			QRCaption:            "This QR code contains the subscription URL for this profile.",
			SubscriptionTitle:    "Subscription",
			SubscriptionHint:     "Best option for client apps that support subscriptions.",
			Open:                 "Open",
			SubscriptionURLAria:  "Subscription URL",
			CopyURL:              "Copy URL",
			OpenInProxyClient:    "Open in a proxy client",
			LinksTitle:           "Connection Links",
			LinksHint:            "Use these when you need to import a single route manually.",
			ConnectionLinkAria:   "Connection link",
			Copy:                 "Copy",
			Copied:               "Copied",
			FooterNote:           "Keep this page URL private. Anyone with the token can read this profile.",
		}
	}
}
