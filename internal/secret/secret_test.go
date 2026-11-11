package secret

import (
	"strings"
	"testing"
)

func sealer(t *testing.T) *Sealer {
	t.Helper()
	t.Setenv(KeyEnv, "a-sufficiently-long-test-key")
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestAValueRoundTrips(t *testing.T) {
	s := sealer(t)

	sealed, err := s.Seal("hunter2-but-longer")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(sealed, "hunter2") {
		t.Fatal("the plaintext is visible in the stored value")
	}

	opened, err := s.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened != "hunter2-but-longer" {
		t.Errorf("opened %q", opened)
	}
}

// Sealing the same value twice must not produce the same output, or anybody
// with read access to the collection can tell that two tenants chose the same
// password without decrypting either.
func TestTheSameValueSealsDifferentlyEachTime(t *testing.T) {
	s := sealer(t)

	a, _ := s.Seal("the-same-password")
	b, _ := s.Seal("the-same-password")

	if a == b {
		t.Error("identical plaintexts produced identical ciphertexts")
	}
}

// A plaintext credential for an administrator account on every machine,
// sitting in a collection that backups copy, is not a slightly-worse outcome
// than an encrypted one. Refusing is the only moment anybody finds out.
func TestNoKeyMeansNothingIsStored(t *testing.T) {
	t.Setenv(KeyEnv, "")

	if _, err := New(); err != ErrNoKey {
		t.Errorf("New with no key returned %v, want ErrNoKey", err)
	}

	var nilSealer *Sealer
	if _, err := nilSealer.Seal("secret"); err != ErrNoKey {
		t.Errorf("Seal on a nil sealer returned %v, want ErrNoKey", err)
	}
}

func TestAShortKeyIsRefused(t *testing.T) {
	t.Setenv(KeyEnv, "short")

	if _, err := New(); err == nil {
		t.Error("a five-character key was accepted — it would look exactly as safe as a good one")
	}
}

// A value that will not open is an error, never an empty string: returning ""
// would silently create an account with an empty password.
func TestAValueThatWillNotOpenIsAnErrorNotAnEmptyString(t *testing.T) {
	s := sealer(t)
	sealed, _ := s.Seal("original")

	t.Setenv(KeyEnv, "a-completely-different-long-key")
	other, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	opened, err := other.Open(sealed)
	if err == nil {
		t.Fatal("a value sealed with another key opened successfully")
	}
	if opened != "" {
		t.Error("it returned something")
	}
	if !strings.Contains(err.Error(), KeyEnv) {
		t.Errorf("the error does not say what to look at: %v", err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	s := sealer(t)
	sealed, _ := s.Seal("original")

	// Flip a character in the ciphertext.
	bad := []byte(sealed)
	if bad[len(bad)-2] == 'A' {
		bad[len(bad)-2] = 'B'
	} else {
		bad[len(bad)-2] = 'A'
	}

	if _, err := s.Open(string(bad)); err == nil {
		t.Error("a modified value opened successfully")
	}
}

func TestAnEmptyValueIsNotSealed(t *testing.T) {
	s := sealer(t)

	sealed, err := s.Seal("")
	if err != nil || sealed != "" {
		t.Errorf("Seal(\"\") = %q, %v; an absent secret should stay absent", sealed, err)
	}
	opened, err := s.Open("")
	if err != nil || opened != "" {
		t.Errorf("Open(\"\") = %q, %v", opened, err)
	}
}
