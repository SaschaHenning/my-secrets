// Package teamkeys reads and writes the team key manifest used by shared
// my-secrets stores.
package teamkeys

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// Filename is the repository-relative name of the team key manifest.
	Filename = "team-keys.yaml"

	maxManifestSize  = 1 << 20
	maxPublicKeySize = 1 << 20
)

// File is a versioned team key manifest.
type File struct {
	Version int      `yaml:"version"`
	Members []Member `yaml:"members"`
}

// Member associates a team member with a GPG fingerprint and an optional
// repository-relative public-key file.
type Member struct {
	Name        string `yaml:"name"`
	Fingerprint string `yaml:"fingerprint"`
	Email       string `yaml:"email"`
	PublicKey   string `yaml:"public_key,omitempty"`
}

type yamlFile struct {
	Version *int     `yaml:"version"`
	Members []Member `yaml:"members"`
}

// Load reads, strictly decodes, validates, and canonicalizes a manifest.
func Load(manifestPath string) (*File, error) {
	data, err := readLimitedRegularFile(manifestPath, maxManifestSize)
	if err != nil {
		return nil, fmt.Errorf("read team key manifest: %w", err)
	}

	file, err := decode(data)
	if err != nil {
		return nil, fmt.Errorf("parse team key manifest: %w", err)
	}
	return file, nil
}

// Save validates and canonicalizes a copy of file, then atomically replaces
// manifestPath with its YAML representation.
func Save(manifestPath string, file *File) error {
	if file == nil {
		return errors.New("save team key manifest: file is nil")
	}

	normalized := &File{
		Version: file.Version,
		Members: append([]Member(nil), file.Members...),
	}
	if err := normalized.Validate(); err != nil {
		return fmt.Errorf("save team key manifest: %w", err)
	}
	data, err := yaml.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("marshal team key manifest: %w", err)
	}
	if err := writeAtomic(manifestPath, data); err != nil {
		return fmt.Errorf("save team key manifest: %w", err)
	}
	return nil
}

// Validate checks the manifest and canonicalizes it in place. A zero Version
// is treated as the current default, version 1.
func (file *File) Validate() error {
	return file.validate(true)
}

func (file *File) validate(defaultVersion bool) error {
	if file == nil {
		return errors.New("team key manifest is nil")
	}

	normalized := File{
		Version: file.Version,
		Members: append([]Member(nil), file.Members...),
	}
	if defaultVersion && normalized.Version == 0 {
		normalized.Version = 1
	}
	if normalized.Version != 1 {
		return fmt.Errorf("unsupported team key manifest version %d", normalized.Version)
	}

	fingerprints := make(map[string]int, len(normalized.Members))
	emails := make(map[string]int, len(normalized.Members))
	for i := range normalized.Members {
		member := &normalized.Members[i]
		member.Name = strings.TrimSpace(member.Name)
		if member.Name == "" {
			return fmt.Errorf("member %d: name is required", i+1)
		}
		if strings.ContainsAny(member.Name, "\x00\r\n") {
			return fmt.Errorf("member %d: name contains a forbidden control character", i+1)
		}

		fingerprint, err := normalizeFingerprint(member.Fingerprint)
		if err != nil {
			return fmt.Errorf("member %d (%q): %w", i+1, member.Name, err)
		}
		member.Fingerprint = fingerprint

		email, err := normalizeEmail(member.Email)
		if err != nil {
			return fmt.Errorf("member %d (%q): %w", i+1, member.Name, err)
		}
		member.Email = email

		if err := validatePublicKeyPath(member.PublicKey); err != nil {
			return fmt.Errorf("member %d (%q): %w", i+1, member.Name, err)
		}

		if previous, ok := fingerprints[member.Fingerprint]; ok {
			return fmt.Errorf(
				"member %d (%q): fingerprint duplicates member %d",
				i+1,
				member.Name,
				previous+1,
			)
		}
		fingerprints[member.Fingerprint] = i

		if previous, ok := emails[member.Email]; ok {
			return fmt.Errorf(
				"member %d (%q): email duplicates member %d",
				i+1,
				member.Name,
				previous+1,
			)
		}
		emails[member.Email] = i
	}

	*file = normalized
	return nil
}

// Fingerprints returns member fingerprints in manifest order.
func (file *File) Fingerprints() []string {
	if file == nil {
		return nil
	}
	fingerprints := make([]string, len(file.Members))
	for i := range file.Members {
		fingerprints[i] = file.Members[i].Fingerprint
	}
	return fingerprints
}

// FindFingerprint returns the first member with fingerprint. Lookup is
// case-insensitive and accepts surrounding whitespace.
func (file *File) FindFingerprint(fingerprint string) (*Member, bool) {
	if file == nil {
		return nil, false
	}
	normalized, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, false
	}
	for i := range file.Members {
		if strings.EqualFold(file.Members[i].Fingerprint, normalized) {
			return &file.Members[i], true
		}
	}
	return nil, false
}

// ResolvePublicKey securely reads member's optional public-key file relative
// to the directory containing manifestPath. An omitted path returns nil, nil.
func ResolvePublicKey(manifestPath string, member Member) ([]byte, error) {
	if member.PublicKey == "" {
		return nil, nil
	}
	if manifestPath == "" {
		return nil, errors.New("resolve public key: manifest path is empty")
	}
	if err := validatePublicKeyPath(member.PublicKey); err != nil {
		return nil, fmt.Errorf("resolve public key: %w", err)
	}

	root, err := os.OpenRoot(filepath.Dir(manifestPath))
	if err != nil {
		return nil, fmt.Errorf("resolve public key: open manifest directory: %w", err)
	}
	defer root.Close()

	relativePath := filepath.FromSlash(member.PublicKey)
	var (
		currentPath string
		finalInfo   os.FileInfo
	)
	segments := strings.Split(member.PublicKey, "/")
	for i, segment := range segments {
		currentPath = filepath.Join(currentPath, segment)
		info, err := root.Lstat(currentPath)
		if err != nil {
			return nil, fmt.Errorf("resolve public key %q: %w", member.PublicKey, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("resolve public key %q: symbolic links are not allowed", member.PublicKey)
		}
		if i < len(segments)-1 {
			if !info.IsDir() {
				return nil, fmt.Errorf(
					"resolve public key %q: path component %q is not a directory",
					member.PublicKey,
					currentPath,
				)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("resolve public key %q: not a regular file", member.PublicKey)
		}
		if info.Size() > maxPublicKeySize {
			return nil, fmt.Errorf(
				"resolve public key %q: file exceeds %d bytes",
				member.PublicKey,
				maxPublicKeySize,
			)
		}
		finalInfo = info
	}

	publicKey, err := root.Open(relativePath)
	if err != nil {
		return nil, fmt.Errorf("resolve public key %q: %w", member.PublicKey, err)
	}
	defer publicKey.Close()

	openedInfo, err := publicKey.Stat()
	if err != nil {
		return nil, fmt.Errorf("resolve public key %q: stat opened file: %w", member.PublicKey, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(finalInfo, openedInfo) {
		return nil, fmt.Errorf("resolve public key %q: file changed while opening", member.PublicKey)
	}

	data, err := io.ReadAll(io.LimitReader(publicKey, maxPublicKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("resolve public key %q: read: %w", member.PublicKey, err)
	}
	if len(data) > maxPublicKeySize {
		return nil, fmt.Errorf(
			"resolve public key %q: file exceeds %d bytes",
			member.PublicKey,
			maxPublicKeySize,
		)
	}
	return data, nil
}

func decode(data []byte) (*File, error) {
	var document yaml.Node
	stream := yaml.NewDecoder(bytes.NewReader(data))
	if err := stream.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("manifest is empty")
		}
		return nil, err
	}
	if document.Kind != yaml.DocumentNode ||
		len(document.Content) != 1 ||
		document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("manifest root must be a mapping")
	}

	var extra yaml.Node
	if err := stream.Decode(&extra); err == nil {
		return nil, errors.New("manifest must contain exactly one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}

	versionNode := mappingValue(document.Content[0], "version")
	if versionNode != nil && versionNode.Tag == "!!null" {
		return nil, errors.New("version must be an integer")
	}
	if versionNode != nil && versionNode.Tag != "!!int" {
		return nil, errors.New("version must be an integer")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var raw yamlFile
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}

	version := 1
	if raw.Version != nil {
		version = *raw.Version
	}
	file := &File{
		Version: version,
		Members: raw.Members,
	}
	if err := file.validate(false); err != nil {
		return nil, err
	}
	return file, nil
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func normalizeFingerprint(fingerprint string) (string, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if len(fingerprint) != 40 {
		return "", errors.New("fingerprint must contain exactly 40 hexadecimal characters")
	}
	for _, char := range fingerprint {
		if !isHex(char) {
			return "", errors.New("fingerprint must contain exactly 40 hexadecimal characters")
		}
	}
	return strings.ToUpper(fingerprint), nil
}

func isHex(char rune) bool {
	return char >= '0' && char <= '9' ||
		char >= 'a' && char <= 'f' ||
		char >= 'A' && char <= 'F'
}

func normalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", errors.New("email is required")
	}
	if strings.ContainsAny(email, "\x00\r\n") {
		return "", errors.New("email contains a forbidden control character")
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Name != "" || address.Address != email {
		return "", errors.New("email is invalid")
	}
	return strings.ToLower(email), nil
}

func validatePublicKeyPath(publicKeyPath string) error {
	if publicKeyPath == "" {
		return nil
	}
	if strings.ContainsAny(publicKeyPath, "\\\x00\r\n") {
		return errors.New("public_key must use slash-separated path segments without control characters")
	}
	if pathpkg.IsAbs(publicKeyPath) || hasWindowsVolumePrefix(publicKeyPath) {
		return errors.New("public_key must be repository-relative")
	}

	segments := strings.Split(publicKeyPath, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("public_key must not contain empty, dot, or traversal path segments")
		}
	}
	if pathpkg.Clean(publicKeyPath) != publicKeyPath {
		return errors.New("public_key must be a canonical slash-relative path")
	}
	return nil
}

func hasWindowsVolumePrefix(value string) bool {
	return len(value) >= 2 &&
		value[1] == ':' &&
		(value[0] >= 'a' && value[0] <= 'z' || value[0] >= 'A' && value[0] <= 'Z')
}

func readLimitedRegularFile(path string, limit int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("path is empty")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("symbolic links are not allowed")
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if pathInfo.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) {
		return nil, errors.New("file changed while opening")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

func writeAtomic(path string, data []byte) error {
	if path == "" {
		return errors.New("path is empty")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create manifest directory: %w", err)
	}

	temp, err := os.CreateTemp(parent, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary manifest: %w", err)
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		_ = temp.Close()
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(0o644); err != nil {
		return fmt.Errorf("set temporary manifest permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write temporary manifest: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary manifest: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary manifest: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace manifest: %w", err)
	}
	cleanup = false
	return nil
}
