package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

func validPubKeyBase64() string {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(key[:])
}

func TestLoad_ValidConfig(t *testing.T) {
	pk := validPubKeyBase64()
	path := writeConfig(t, `{
		"relay_url": "https://relay.example.com",
		"post_token": "shared-secret-token",
		"guardians": [
			{"id": "guardian-1", "pub_key": "`+pk+`"},
			{"id": "guardian-2", "pub_key": "`+pk+`"},
			{"id": "guardian-3", "pub_key": "`+pk+`"}
		]
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.RelayURL != "https://relay.example.com" {
		t.Errorf("unexpected RelayURL: %s", cfg.RelayURL)
	}
	if cfg.PostToken != "shared-secret-token" {
		t.Errorf("unexpected PostToken: %s", cfg.PostToken)
	}
	if len(cfg.Guardians) != 3 {
		t.Fatalf("expected 3 guardians, got %d", len(cfg.Guardians))
	}
	if cfg.Guardians[0].ID != "guardian-1" {
		t.Errorf("unexpected first guardian ID: %s", cfg.Guardians[0].ID)
	}
}

func TestLoad_RejectsMissingRelayURL(t *testing.T) {
	pk := validPubKeyBase64()
	path := writeConfig(t, `{
		"relay_url": "",
		"post_token": "shared-secret-token",
		"guardians": [
			{"id": "g1", "pub_key": "`+pk+`"},
			{"id": "g2", "pub_key": "`+pk+`"},
			{"id": "g3", "pub_key": "`+pk+`"}
		]
	}`)

	if _, err := Load(path); err != ErrMissingRelayURL {
		t.Fatalf("expected ErrMissingRelayURL, got %v", err)
	}
}

func TestLoad_RejectsMissingPostToken(t *testing.T) {
	pk := validPubKeyBase64()
	path := writeConfig(t, `{
		"relay_url": "https://relay.example.com",
		"post_token": "",
		"guardians": [
			{"id": "g1", "pub_key": "`+pk+`"},
			{"id": "g2", "pub_key": "`+pk+`"},
			{"id": "g3", "pub_key": "`+pk+`"}
		]
	}`)

	if _, err := Load(path); err != ErrMissingPostToken {
		t.Fatalf("expected ErrMissingPostToken, got %v", err)
	}
}

func TestLoad_RejectsWrongGuardianCount(t *testing.T) {
	pk := validPubKeyBase64()
	path := writeConfig(t, `{
		"relay_url": "https://relay.example.com",
		"post_token": "shared-secret-token",
		"guardians": [
			{"id": "g1", "pub_key": "`+pk+`"},
			{"id": "g2", "pub_key": "`+pk+`"}
		]
	}`)

	if _, err := Load(path); err != ErrWrongGuardianCount {
		t.Fatalf("expected ErrWrongGuardianCount, got %v", err)
	}
}

func TestLoad_RejectsInvalidPubKey(t *testing.T) {
	path := writeConfig(t, `{
		"relay_url": "https://relay.example.com",
		"post_token": "shared-secret-token",
		"guardians": [
			{"id": "g1", "pub_key": "not-valid-base64!!"},
			{"id": "g2", "pub_key": "aGVsbG8="},
			{"id": "g3", "pub_key": "aGVsbG8="}
		]
	}`)

	if _, err := Load(path); err != ErrInvalidPubKey {
		t.Fatalf("expected ErrInvalidPubKey, got %v", err)
	}
}

func TestLoad_RejectsDuplicateGuardianIDs(t *testing.T) {
	pk := validPubKeyBase64()
	path := writeConfig(t, `{
		"relay_url": "https://relay.example.com",
		"post_token": "shared-secret-token",
		"guardians": [
			{"id": "same-id", "pub_key": "`+pk+`"},
			{"id": "same-id", "pub_key": "`+pk+`"},
			{"id": "g3", "pub_key": "`+pk+`"}
		]
	}`)

	if _, err := Load(path); err != ErrDuplicateGuardian {
		t.Fatalf("expected ErrDuplicateGuardian, got %v", err)
	}
}

func TestLoad_ErrorsOnMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/path/config.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_ErrorsOnMalformedJSON(t *testing.T) {
	path := writeConfig(t, `{not valid json`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestLoad_PubKeyBytesDecodedCorrectly(t *testing.T) {
	var expected [32]byte
	for i := range expected {
		expected[i] = byte(i * 2)
	}
	pk := base64.StdEncoding.EncodeToString(expected[:])

	path := writeConfig(t, `{
		"relay_url": "https://relay.example.com",
		"post_token": "shared-secret-token",
		"guardians": [
			{"id": "g1", "pub_key": "`+pk+`"},
			{"id": "g2", "pub_key": "`+pk+`"},
			{"id": "g3", "pub_key": "`+pk+`"}
		]
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Guardians[0].PubKey != expected {
		t.Errorf("pub key bytes did not decode correctly: got %v, want %v", cfg.Guardians[0].PubKey, expected)
	}
}

func TestFingerprint_IsDeterministic(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	fp1 := Fingerprint(key)
	fp2 := Fingerprint(key)
	if fp1 != fp2 {
		t.Fatalf("expected deterministic fingerprint, got %q and %q", fp1, fp2)
	}
}

func TestFingerprint_DiffersForDifferentKeys(t *testing.T) {
	var key1, key2 [32]byte
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}
	fp1 := Fingerprint(key1)
	fp2 := Fingerprint(key2)
	if fp1 == fp2 {
		t.Fatal("expected different keys to produce different fingerprints")
	}
}

func TestFingerprint_HasReadableGroupedFormat(t *testing.T) {
	var key [32]byte
	fp := Fingerprint(key)

	groups := strings.Split(fp, " ")
	if len(groups) != 8 {
		t.Fatalf("expected 8 groups, got %d: %q", len(groups), fp)
	}
	for _, g := range groups {
		if len(g) != 4 {
			t.Fatalf("expected each group to be 4 characters, got %q in %q", g, fp)
		}
	}
}

func TestGuardian_FingerprintMethodMatchesPackageFunction(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	g := Guardian{ID: "test-guardian", PubKey: key}

	if g.Fingerprint() != Fingerprint(key) {
		t.Fatalf("Guardian.Fingerprint() = %q, want %q", g.Fingerprint(), Fingerprint(key))
	}
}

