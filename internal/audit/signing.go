// Package audit — signing.go implements the optional Ed25519-signed
// hash-chain mode. It is opt-in via the MYS_AUDIT_SIGN=1 environment
// variable.
//
// Row canonicalisation
// --------------------
// For a given audit row the canonical byte sequence fed into SHA-256 is:
//
//	seq|ts|action|secret_path|org|actor_kind|actor_detail|result|reason
//
// Each field is the string form of the column value, joined by ASCII '\n'
// (U+000A) — NOT a trailing newline. `ts` is always the RFC3339Nano UTC
// representation, identical to what is stored in the `ts` column.
// `actor_detail` is the raw JSON bytes (or the empty string if NULL).
//
// row_hash_n  = SHA-256( canonical_bytes_n || prev_hash_n )
// prev_hash_n = row_hash_{n-1}  (32 zero bytes for the very first signed row)
// signature_n = Ed25519-Sign(priv, row_hash_n)
//
// The verifier must reconstruct the canonical bytes in exactly this order,
// using the values read back from the DB.
package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// EnvSignMode is the opt-in flag. Set to "1" (or "true") to enable the
// signed hash-chain mode at Open time.
const EnvSignMode = "MYS_AUDIT_SIGN"

// Keychain coordinates for the Ed25519 audit signing key (private half).
const (
	KeychainService = "com.jasp.my-secrets.audit-signing"
	KeychainAccount = "default"
)

// KeyStore abstracts the source of the Ed25519 signing keypair so tests
// can substitute an in-memory key without touching the real keychain.
type KeyStore interface {
	// Load returns the private key. Implementations may lazily generate
	// a new keypair and persist it on first call.
	Load() (ed25519.PrivateKey, error)
	// Public returns the matching public key.
	Public() (ed25519.PublicKey, error)
}

// MemoryKeyStore is an in-process KeyStore used by tests and as a last-
// resort fallback when the OS keychain is unavailable.
type MemoryKeyStore struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

// NewMemoryKeyStore generates a fresh Ed25519 keypair held only in memory.
func NewMemoryKeyStore() (*MemoryKeyStore, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MemoryKeyStore{Priv: priv, Pub: pub}, nil
}

func (m *MemoryKeyStore) Load() (ed25519.PrivateKey, error) { return m.Priv, nil }
func (m *MemoryKeyStore) Public() (ed25519.PublicKey, error) {
	if m.Pub != nil {
		return m.Pub, nil
	}
	return m.Priv.Public().(ed25519.PublicKey), nil
}

// keychainKeyStore persists the private key in the OS keychain (macOS
// Keychain via zalando/go-keyring) and the public key in a file next to
// the audit DB for offline verification.
type keychainKeyStore struct {
	service    string
	account    string
	pubKeyPath string
}

// DefaultPublicKeyPath returns the canonical location of the audit
// public-key file: ~/.local/share/my-secrets/audit-pub.key.
func DefaultPublicKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "my-secrets", "audit-pub.key"), nil
}

// NewKeychainKeyStore builds a keychain-backed keystore. The private key
// is stored under (service, account); the public key is written to
// pubKeyPath in base64 form.
func NewKeychainKeyStore(service, account, pubKeyPath string) *keychainKeyStore {
	return &keychainKeyStore{service: service, account: account, pubKeyPath: pubKeyPath}
}

// DefaultKeyStore wires NewKeychainKeyStore to the default service/account
// and the default public-key file path.
func DefaultKeyStore() (KeyStore, error) {
	pkPath, err := DefaultPublicKeyPath()
	if err != nil {
		return nil, err
	}
	return NewKeychainKeyStore(KeychainService, KeychainAccount, pkPath), nil
}

// Load returns the private key, generating + persisting a fresh pair on
// first call.
func (k *keychainKeyStore) Load() (ed25519.PrivateKey, error) {
	raw, err := keyring.Get(k.service, k.account)
	if err == nil {
		decoded, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if derr != nil {
			return nil, fmt.Errorf("decode keychain key: %w", derr)
		}
		if len(decoded) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("unexpected keychain key length: %d (want %d)",
				len(decoded), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(decoded), nil
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return nil, fmt.Errorf("keychain access: %w", err)
	}
	// Generate a new pair on first use.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(priv)
	if err := keyring.Set(k.service, k.account, encoded); err != nil {
		return nil, fmt.Errorf("store private key in keychain: %w", err)
	}
	if err := writePublicKeyFile(k.pubKeyPath, pub); err != nil {
		return nil, err
	}
	return priv, nil
}

// Public returns the public key. Prefers the file written alongside the
// keychain entry; falls back to deriving it from the private key.
func (k *keychainKeyStore) Public() (ed25519.PublicKey, error) {
	if b, err := os.ReadFile(k.pubKeyPath); err == nil {
		decoded, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil {
			return nil, fmt.Errorf("decode audit pub key file: %w", derr)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("unexpected pub key length: %d", len(decoded))
		}
		return ed25519.PublicKey(decoded), nil
	}
	priv, err := k.Load()
	if err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("priv key does not yield ed25519 public key")
	}
	// Opportunistically persist for next time.
	_ = writePublicKeyFile(k.pubKeyPath, pub)
	return pub, nil
}

func writePublicKeyFile(path string, pub ed25519.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir audit pub dir: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(pub)
	return os.WriteFile(path, []byte(enc+"\n"), 0o644)
}

// canonicalBytes builds the byte sequence fed into the chain hash. See
// the package doc at the top of this file for the exact format.
func canonicalBytes(e Entry) []byte {
	var detail string
	if len(e.ActorDetail) > 0 {
		detail = string(e.ActorDetail)
	}
	parts := []string{
		fmt.Sprintf("%d", e.Seq),
		e.TS.UTC().Format(time.RFC3339Nano),
		e.Action,
		e.SecretPath,
		e.Org,
		e.ActorKind,
		detail,
		e.Result,
		e.Reason,
	}
	return []byte(strings.Join(parts, "\n"))
}

// chainHash hashes canonicalBytes(e) || prev. prev may be nil; a nil prev
// is treated as 32 zero bytes.
func chainHash(e Entry, prev []byte) []byte {
	h := sha256.New()
	h.Write(canonicalBytes(e))
	if len(prev) == 0 {
		var zero [32]byte
		h.Write(zero[:])
	} else {
		h.Write(prev)
	}
	sum := h.Sum(nil)
	return sum
}

// envSignEnabled returns true if the env var opts the process into the
// signed chain mode.
func envSignEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvSignMode)))
	return v == "1" || v == "true" || v == "yes"
}
