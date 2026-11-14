package identity

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/milad-raeisi/LANChat/internal/platform"
)

func TestGenerateSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	id, created, err := LoadOrCreate(path)
	if err != nil || !created {
		t.Fatalf("LoadOrCreate: created=%v err=%v", created, err)
	}
	if err := platform.CheckPrivateFile(path); err != nil {
		t.Fatalf("key file permissions: %v", err)
	}
	again, created, err := LoadOrCreate(path)
	if err != nil || created {
		t.Fatalf("second LoadOrCreate must load, created=%v err=%v", created, err)
	}
	if again.ID() != id.ID() || again.Fingerprint() != id.Fingerprint() {
		t.Fatal("identity changed across loads")
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "Peer-ID: "+string(id.ID())) {
		t.Fatalf("missing Peer-ID header: %s", b)
	}
}

func TestLoadMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "none")); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("expected ErrNoIdentity, got %v", err)
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("not pem"), 0o600)
	if _, err := Load(bad); err == nil {
		t.Fatal("expected error for corrupt key")
	}
}

func TestPeerIDFormat(t *testing.T) {
	id, _ := Generate()
	if len(id.ID()) != PeerIDLen {
		t.Fatalf("len=%d", len(id.ID()))
	}
	if !regexp.MustCompile(`^[a-z2-7]{32}$`).MatchString(string(id.ID())) {
		t.Fatalf("bad id %q", id.ID())
	}
	if _, err := ParsePeerID(string(id.ID())); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "ABC", strings.Repeat("a", 31), strings.Repeat("1", 32), strings.Repeat("a", 31) + "/"} {
		if _, err := ParsePeerID(bad); err == nil {
			t.Fatalf("ParsePeerID(%q) accepted", bad)
		}
	}
	if IDFromPublicKey(id.PublicKey()) != id.ID() {
		t.Fatal("ID not reproducible")
	}
}

func TestCertificateBindsKey(t *testing.T) {
	id, _ := Generate()
	cert, err := id.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(id.PublicKey()) {
		t.Fatal("certificate does not carry the identity key")
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("self-signature invalid: %v", err)
	}
}

func TestSASSymmetricAndSessionBound(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	ex := []byte("exporter-secret-0123456789abcdef")
	s1 := SAS(SPKI(a.PublicKey()), SPKI(b.PublicKey()), ex)
	s2 := SAS(SPKI(b.PublicKey()), SPKI(a.PublicKey()), ex)
	if s1 != s2 {
		t.Fatalf("SAS not symmetric: %s vs %s", s1, s2)
	}
	if !regexp.MustCompile(`^\d{3} \d{3}$`).MatchString(s1) {
		t.Fatalf("bad SAS format %q", s1)
	}
	s3 := SAS(SPKI(a.PublicKey()), SPKI(b.PublicKey()), []byte("other-session"))
	m, _ := Generate()
	s4 := SAS(SPKI(a.PublicKey()), SPKI(m.PublicKey()), ex)
	if s3 == s1 && s4 == s1 {
		t.Fatal("SAS does not depend on session or keys")
	}
}

func TestFingerprintFormatting(t *testing.T) {
	fp := strings.Repeat("ab12", 16)
	f := FormatFingerprint(fp)
	if strings.Count(f, " ") != 15 {
		t.Fatalf("unexpected format %q", f)
	}
	if NormalizeFingerprint(strings.ToUpper(f)) != fp {
		t.Fatal("normalize round trip failed")
	}
}
