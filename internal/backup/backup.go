package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/emilmelnikov/xray-easy/internal/config"
	"github.com/emilmelnikov/xray-easy/internal/users"
)

const (
	FormatVersion = 1

	manifestName = "manifest.json"
	configName   = "config.json"
	usersName    = "users.json"
	certsDirName = "certs"
)

type CreateOptions struct {
	ConfigPath string
	UsersPath  string
	OutputPath string
	Now        time.Time
}

type RestoreOptions struct {
	ConfigPath  string
	UsersPath   string
	ArchivePath string
}

type Manifest struct {
	Version             int       `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
	Role                string    `json:"role"`
	HasUsers            bool      `json:"has_users"`
	HasCertificateCache bool      `json:"has_certificate_cache"`
}

func Create(opts CreateOptions) error {
	if opts.ConfigPath == "" {
		return errors.New("config path is required")
	}
	if opts.OutputPath == "" {
		return errors.New("backup output path is required")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}

	hasUsers := false
	if cfg.Role == config.RoleMain {
		if opts.UsersPath == "" {
			return errors.New("users path is required for main config backup")
		}
		file, err := users.Load(opts.UsersPath)
		if err != nil {
			return err
		}
		if err := file.Validate(cfg); err != nil {
			return err
		}
		hasUsers = true
	}

	certCachePath := resolveConfigRelativePath(cfg.Certificate.CacheDir, opts.ConfigPath)
	hasCertCache := false
	if cfg.Role == config.RoleMain {
		info, err := os.Stat(certCachePath)
		switch {
		case err == nil && info.IsDir():
			hasCertCache = true
		case err == nil:
			return fmt.Errorf("certificate cache %q is not a directory", certCachePath)
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("stat certificate cache %q: %w", certCachePath, err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for backup %q: %w", opts.OutputPath, err)
	}
	if _, err := os.Stat(opts.OutputPath); err == nil {
		return fmt.Errorf("backup %q already exists", opts.OutputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat backup %q: %w", opts.OutputPath, err)
	}
	out, err := os.CreateTemp(filepath.Dir(opts.OutputPath), ".xray-easy-backup-*")
	if err != nil {
		return fmt.Errorf("create temporary backup %q: %w", opts.OutputPath, err)
	}
	tmpPath := out.Name()
	defer out.Close()
	defer os.Remove(tmpPath)

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	manifest := Manifest{
		Version:             FormatVersion,
		CreatedAt:           opts.Now,
		Role:                cfg.Role,
		HasUsers:            hasUsers,
		HasCertificateCache: hasCertCache,
	}
	if err := addJSON(tw, manifestName, manifest, opts.Now); err != nil {
		return err
	}
	if err := addFile(tw, opts.ConfigPath, configName); err != nil {
		return err
	}
	if hasUsers {
		if err := addFile(tw, opts.UsersPath, usersName); err != nil {
			return err
		}
	}
	if hasCertCache {
		if err := addDir(tw, certCachePath, certsDirName); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar backup %q: %w", opts.OutputPath, err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip backup %q: %w", opts.OutputPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close backup %q: %w", opts.OutputPath, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod backup %q: %w", opts.OutputPath, err)
	}
	if err := os.Rename(tmpPath, opts.OutputPath); err != nil {
		return fmt.Errorf("replace backup %q: %w", opts.OutputPath, err)
	}
	return nil
}

func Restore(opts RestoreOptions) error {
	if opts.ConfigPath == "" {
		return errors.New("config path is required")
	}
	if opts.ArchivePath == "" {
		return errors.New("backup archive path is required")
	}

	tmp, err := os.MkdirTemp("", "xray-easy-restore-*")
	if err != nil {
		return fmt.Errorf("create restore temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	manifest, err := extract(opts.ArchivePath, tmp)
	if err != nil {
		return err
	}
	if manifest.Version != FormatVersion {
		return fmt.Errorf("unsupported backup format version %d", manifest.Version)
	}

	tmpConfigPath := filepath.Join(tmp, configName)
	cfg, err := config.Load(tmpConfigPath)
	if err != nil {
		return err
	}
	if cfg.Role != manifest.Role {
		return fmt.Errorf("backup manifest role %q does not match config role %q", manifest.Role, cfg.Role)
	}

	tmpUsersPath := filepath.Join(tmp, usersName)
	if cfg.Role == config.RoleMain {
		if opts.UsersPath == "" {
			return errors.New("users path is required for main config restore")
		}
		file, err := users.Load(tmpUsersPath)
		if err != nil {
			return err
		}
		if err := file.Validate(cfg); err != nil {
			return err
		}
	}

	if cfg.Role == config.RoleMain && manifest.HasCertificateCache {
		src := filepath.Join(tmp, certsDirName)
		dst := resolveConfigRelativePath(cfg.Certificate.CacheDir, opts.ConfigPath)
		if err := copyDir(src, dst); err != nil {
			return err
		}
	}
	if err := restoreFile(tmpConfigPath, opts.ConfigPath, 0o600); err != nil {
		return err
	}
	if cfg.Role == config.RoleMain {
		if err := restoreFile(tmpUsersPath, opts.UsersPath, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func addJSON(tw *tar.Writer, name string, value any, modTime time.Time) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	header := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: modTime,
	}
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %q: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write tar file %q: %w", name, err)
	}
	return nil
}

func addFile(tw *tar.Writer, sourcePath string, archiveName string) error {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return fmt.Errorf("stat %q: %w", sourcePath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", sourcePath)
	}
	file, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open %q: %w", sourcePath, err)
	}
	defer file.Close()

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("create tar header for %q: %w", sourcePath, err)
	}
	header.Name = archiveName
	header.Mode = int64(info.Mode().Perm())
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %q: %w", archiveName, err)
	}
	if _, err := io.Copy(tw, file); err != nil {
		return fmt.Errorf("write tar file %q: %w", archiveName, err)
	}
	return nil
}

func addDir(tw *tar.Writer, sourceDir string, archiveDir string) error {
	var paths []string
	if err := filepath.WalkDir(sourceDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		return fmt.Errorf("walk %q: %w", sourceDir, err)
	}
	sort.Strings(paths)

	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("stat %q: %w", path, err)
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(archiveDir, rel))
		if rel == "." {
			name = archiveDir
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("create tar header for %q: %w", path, err)
		}
		header.Name = name
		header.Mode = int64(info.Mode().Perm())
		if info.IsDir() {
			header.Name += "/"
			if err := tw.WriteHeader(header); err != nil {
				return fmt.Errorf("write tar header %q: %w", name, err)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%q is not a regular file", path)
		}
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header %q: %w", name, err)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %q: %w", path, err)
		}
		if _, err := io.Copy(tw, file); err != nil {
			_ = file.Close()
			return fmt.Errorf("write tar file %q: %w", name, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close %q: %w", path, err)
		}
	}
	return nil
}

func extract(archivePath string, destDir string) (Manifest, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return Manifest{}, fmt.Errorf("open backup %q: %w", archivePath, err)
	}
	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return Manifest{}, fmt.Errorf("read gzip backup %q: %w", archivePath, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var manifest Manifest
	hasManifest := false
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("read backup %q: %w", archivePath, err)
		}
		name, err := cleanArchiveName(header.Name)
		if err != nil {
			return Manifest{}, err
		}
		if !allowedArchiveName(name) {
			return Manifest{}, fmt.Errorf("unexpected backup entry %q", name)
		}
		target := filepath.Join(destDir, filepath.FromSlash(name))
		switch header.Typeflag {
		case tar.TypeDir:
			if name == manifestName || name == configName || name == usersName {
				return Manifest{}, fmt.Errorf("unexpected directory entry %q", name)
			}
			if err := os.MkdirAll(target, fs.FileMode(header.Mode)&0o777); err != nil {
				return Manifest{}, fmt.Errorf("mkdir %q: %w", target, err)
			}
		case tar.TypeReg:
			if name == certsDirName {
				return Manifest{}, fmt.Errorf("unexpected file entry %q", name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return Manifest{}, fmt.Errorf("mkdir for %q: %w", target, err)
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fs.FileMode(header.Mode)&0o777)
			if err != nil {
				return Manifest{}, fmt.Errorf("create %q: %w", target, err)
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return Manifest{}, fmt.Errorf("extract %q: %w", name, copyErr)
			}
			if closeErr != nil {
				return Manifest{}, fmt.Errorf("close %q: %w", target, closeErr)
			}
			if name == manifestName {
				data, err := os.ReadFile(target)
				if err != nil {
					return Manifest{}, err
				}
				if err := json.Unmarshal(data, &manifest); err != nil {
					return Manifest{}, fmt.Errorf("decode backup manifest: %w", err)
				}
				hasManifest = true
			}
		default:
			return Manifest{}, fmt.Errorf("unsupported backup entry type %q for %q", header.Typeflag, name)
		}
	}
	if !hasManifest {
		return Manifest{}, errors.New("backup manifest is missing")
	}
	return manifest, nil
}

func cleanArchiveName(name string) (string, error) {
	name = filepath.ToSlash(name)
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe backup entry %q", name)
	}
	parts := strings.Split(name, "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			return "", fmt.Errorf("unsafe backup entry %q", name)
		default:
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return "", fmt.Errorf("unsafe backup entry %q", name)
	}
	return strings.Join(clean, "/"), nil
}

func allowedArchiveName(name string) bool {
	return name == manifestName || name == configName || name == usersName || name == certsDirName || strings.HasPrefix(name, certsDirName+"/")
}

func copyDir(sourceDir string, destDir string) error {
	return filepath.WalkDir(sourceDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(destDir, rel)
		if entry.IsDir() {
			return os.MkdirAll(dest, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%q is not a regular file", path)
		}
		return restoreFile(path, dest, info.Mode().Perm())
	})
}

func restoreFile(sourcePath string, destPath string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for %q: %w", destPath, err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open %q: %w", sourcePath, err)
	}
	defer source.Close()

	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".restore-*")
	if err != nil {
		return fmt.Errorf("create temp file for %q: %w", destPath, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmp, source); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy %q to %q: %w", sourcePath, destPath, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file for %q: %w", destPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file for %q: %w", destPath, err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("replace %q: %w", destPath, err)
	}
	return nil
}

func resolveConfigRelativePath(path string, configPath string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(filepath.Dir(configPath), path)
}
