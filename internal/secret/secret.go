// Package secret seals values that have to be stored and read back.
//
// Most credentials in this product are never stored: a password typed in the
// portal to create one account travels to the endpoint, is used once, and is
// gone. That is the right design wherever it fits, and it fits most places.
//
// It does not fit a DEFAULT account applied to machines that have not been
// enrolled yet. The password has to survive until a machine arrives, which
// means it has to be stored, and the endpoint needs the real characters —
// so a hash is no use. Reversible storage is the requirement, not a shortcut.
//
// What that leaves is: encrypt it at rest, with a key that is not in the
// database. AES-GCM with a key from the environment, and a refusal to store
// anything at all when no key is configured — because the alternative to an
// encrypted password is not a slightly-less-safe password, it is a plaintext
// credential for an administrator account on every machine in the fleet,
// sitting in a collection that database backups copy.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// KeyEnv is the environment variable holding the sealing key.
const KeyEnv = "CONFIG_ENCRYPT_KEY"

// minKeyLength is the shortest key accepted.
//
// The key is hashed to 32 bytes either way, so a short one is not a format
// error — it is a weak key that would look identical to a strong one. Refusing
// it is the only moment anybody finds out.
const minKeyLength = 16

// ErrNoKey means nothing can be sealed because no key is configured.
//
// Its own error so a caller can tell an operator what to do about it rather
// than reporting "could not save".
var ErrNoKey = errors.New("no " + KeyEnv + " is configured, so secrets cannot be stored")

// Sealer encrypts and decrypts stored values.
type Sealer struct {
	aead cipher.AEAD
}

// New builds a sealer from the environment.
//
// Returns ErrNoKey when the variable is absent or too short. The caller is
// expected to carry on without the features that need it rather than refuse
// to start: a server that will not boot because an optional feature has no
// key is a worse failure than the feature being unavailable.
func New() (*Sealer, error) {
	key := strings.TrimSpace(os.Getenv(KeyEnv))
	if key == "" {
		return nil, ErrNoKey
	}
	if len(key) < minKeyLength {
		return nil, fmt.Errorf("%s must be at least %d characters", KeyEnv, minKeyLength)
	}

	// Hashed to exactly 32 bytes so any passphrase works, rather than making
	// an operator produce a key of a particular length and get it wrong.
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("building the cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("building the cipher: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts a value for storage.
//
// The nonce is random per call and travels with the ciphertext, so sealing
// the same password twice produces different output — otherwise anybody with
// read access to the collection could tell that two tenants chose the same
// password without decrypting either.
func (s *Sealer) Seal(plain string) (string, error) {
	if s == nil {
		return "", ErrNoKey
	}
	if plain == "" {
		return "", nil
	}

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating a nonce: %w", err)
	}

	sealed := s.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open decrypts a stored value.
//
// A value that will not open is an error, never an empty string: the key
// changed, or the record was tampered with, and both are things somebody has
// to know about. Returning "" would silently create an account with an empty
// password.
func (s *Sealer) Open(sealed string) (string, error) {
	if s == nil {
		return "", ErrNoKey
	}
	if sealed == "" {
		return "", nil
	}

	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("the stored value is not readable: %w", err)
	}
	if len(raw) < s.aead.NonceSize() {
		return "", errors.New("the stored value is too short to be valid")
	}

	nonce, body := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, body, nil)
	if err != nil {
		return "", fmt.Errorf("the stored value could not be decrypted — "+
			"%s may have changed since it was saved", KeyEnv)
	}
	return string(plain), nil
}
