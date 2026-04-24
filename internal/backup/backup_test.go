package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/users"
)

const (
	testPrivateKey = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
	testShortID    = "0123456789abcdef"
)

func TestCreateAndRestoreMainBackup(t *testing.T) {
	sourceDir := t.TempDir()
	configPath := filepath.Join(sourceDir, "config.json")
	usersPath := filepath.Join(sourceDir, "users.json")
	certDir := filepath.Join(sourceDir, "certs")
	backupPath := filepath.Join(t.TempDir(), "backup.tar.gz")

	cfg := testMainConfig()
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("config.Save() error = %v", err)
	}
	file := &users.File{Users: []users.User{
		{
			Username: "alice",
			Token:    "token-1",
			Clients: []users.Client{
				{Route: "main", UUID: "aaaaaaaa-bbbb-0001-dddd-eeeeeeeeeeee"},
			},
		},
	}}
	if err := users.Save(usersPath, file); err != nil {
		t.Fatalf("users.Save() error = %v", err)
	}
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(certs) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "account.json"), []byte(`{"key":"value"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(account.json) error = %v", err)
	}

	err := Create(CreateOptions{
		ConfigPath: configPath,
		UsersPath:  usersPath,
		OutputPath: backupPath,
		Now:        time.Unix(123, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	restoreDir := t.TempDir()
	restoreConfigPath := filepath.Join(restoreDir, "config.json")
	restoreUsersPath := filepath.Join(restoreDir, "users.json")
	if err := Restore(RestoreOptions{
		ConfigPath:  restoreConfigPath,
		UsersPath:   restoreUsersPath,
		ArchivePath: backupPath,
	}); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	restoredConfig, err := config.Load(restoreConfigPath)
	if err != nil {
		t.Fatalf("config.Load(restored) error = %v", err)
	}
	if restoredConfig.Inbound.ServerName != "main.example.com" {
		t.Fatalf("restored server name = %q, want main.example.com", restoredConfig.Inbound.ServerName)
	}
	restoredUsers, err := users.Load(restoreUsersPath)
	if err != nil {
		t.Fatalf("users.Load(restored) error = %v", err)
	}
	if err := restoredUsers.Validate(restoredConfig); err != nil {
		t.Fatalf("restored users Validate() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(restoreDir, "certs", "account.json"))
	if err != nil {
		t.Fatalf("ReadFile(restored account.json) error = %v", err)
	}
	if string(data) != `{"key":"value"}` {
		t.Fatalf("restored account.json = %q", string(data))
	}
}

func TestRestoreRejectsUnsafeArchiveEntry(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "unsafe.tar.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "../evil", Mode: 0o600, Size: 4, Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close() error = %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	if err := os.WriteFile(archivePath, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile(archive) error = %v", err)
	}

	err := Restore(RestoreOptions{
		ConfigPath:  filepath.Join(dir, "config.json"),
		UsersPath:   filepath.Join(dir, "users.json"),
		ArchivePath: archivePath,
	})
	if err == nil {
		t.Fatal("Restore() error = nil, want unsafe entry error")
	}
}

func testMainConfig() *config.Config {
	return &config.Config{
		Role:       config.RoleMain,
		HTTPListen: config.DefaultHTTPListen,
		Certificate: config.Certificate{
			HTTPListen: config.DefaultCertHTTPListen,
			CacheDir:   config.DefaultCertCache,
			CADirURL:   config.DefaultCADirURL,
		},
		Inbound: config.Inbound{
			Listen:     ":443",
			ServerName: "main.example.com",
			PrivateKey: testPrivateKey,
			ShortID:    testShortID,
		},
		Routes: []config.RouteEntry{
			{ID: 1, Name: "main", Title: "main", Outbound: config.Outbound{Type: config.OutboundTypeFreedom}},
		},
	}
}
