// Package identity manages the persistent Ed25519 peer identity: key
// generation and storage, peer ID and fingerprint derivation, the
// self-signed TLS certificate bound to the key, and short authentication
// strings used during pairing.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/milad-raeisi/LANChat/internal/platform"
)

// PeerID is the stable identifier of a LANChat installation. It is the
// lowercase, unpadded base32 encoding of the first 20 bytes of
// SHA-256(SubjectPublicKeyInfo) of the identity key, so it is 32 characters
// long and can be recomputed from any certificate presented by the peer.
type PeerID string

// PeerIDLen is the length of a textual PeerID.
const PeerIDLen = 32

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrInvalidPeerID is returned for malformed peer IDs received from the network.
var ErrInvalidPeerID = errors.New("invalid peer id")

// ParsePeerID validates a textual peer ID.
func ParsePeerID(s string) (PeerID, error) {
	if len(s) != PeerIDLen {
		return "", ErrInvalidPeerID
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			return "", ErrInvalidPeerID
		}
	}
	return PeerID(s), nil
}

// Short returns an abbreviated form used to disambiguate equal display names.
func (p PeerID) Short() string {
	if len(p) < 6 {
		return string(p)
	}
	return strings.ToUpper(string(p[:6]))
}

func (p PeerID) String() string { return string(p) }

// SPKI returns the DER SubjectPublicKeyInfo encoding of an Ed25519 key.
func SPKI(pub ed25519.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// Marshalling a well-formed Ed25519 public key cannot fail.
		panic(fmt.Sprintf("marshal ed25519 public key: %v", err))
	}
	return der
}

// IDFromPublicKey derives the PeerID of a public key.
func IDFromPublicKey(pub ed25519.PublicKey) PeerID {
	sum := sha256.Sum256(SPKI(pub))
	return PeerID(b32.EncodeToString(sum[:20]))
}

// FingerprintSPKI returns the lowercase hex SHA-256 of a DER
// SubjectPublicKeyInfo. The same definition is used for peer identities and
// for pinning the managed discovery server certificate.
func FingerprintSPKI(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// Fingerprint returns the hex SHA-256 fingerprint of an Ed25519 key.
func Fingerprint(pub ed25519.PublicKey) string {
	return FingerprintSPKI(SPKI(pub))
}

// FormatFingerprint groups a hex fingerprint into blocks of four for reading
// aloud, e.g. "3f2a 91c0 …".
func FormatFingerprint(fp string) string {
	fp = NormalizeFingerprint(fp)
	var b strings.Builder
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + 4
		if end > len(fp) {
			end = len(fp)
		}
		b.WriteString(fp[i:end])
	}
	return b.String()
}

// NormalizeFingerprint strips separators and lowercases a fingerprint.
func NormalizeFingerprint(fp string) string {
	r := strings.NewReplacer(" ", "", ":", "", "-", "")
	return strings.ToLower(r.Replace(strings.TrimSpace(fp)))
}

// Identity is a loaded private identity.
type Identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   PeerID
}

// Generate creates a new random identity.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate identity key: %w", err)
	}
	return &Identity{priv: priv, pub: pub, id: IDFromPublicKey(pub)}, nil
}

// FromPrivateKey wraps an existing key (used by tests and loaders).
func FromPrivateKey(priv ed25519.PrivateKey) *Identity {
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{priv: priv, pub: pub, id: IDFromPublicKey(pub)}
}

// ID returns the peer ID.
func (i *Identity) ID() PeerID { return i.id }

// PublicKey returns the public key.
func (i *Identity) PublicKey() ed25519.PublicKey { return i.pub }

// Fingerprint returns the hex SHA-256 fingerprint.
func (i *Identity) Fingerprint() string { return Fingerprint(i.pub) }

// Sign signs msg with the identity key.
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.priv, msg) }

// Certificate returns a self-signed X.509 certificate for the identity key,
// suitable for TLS 1.3. Peers authenticate the key itself, not the
// certificate's validity period, so a wide validity window is used to avoid
// any dependence on synchronised clocks.
func (i *Identity) Certificate() (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "lanchat " + string(i.id)},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2120, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"lanchat"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, i.pub, i.priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: i.priv, Leaf: leaf}, nil
}

const (
	pemTypePlain    = "PRIVATE KEY"
	pemTypeProtectd = "LANCHAT DPAPI PRIVATE KEY"
)

// Save writes the identity to path with owner-only permissions. On Windows
// the key is additionally encrypted with DPAPI (bound to the user account).
func (i *Identity) Save(path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(i.priv)
	if err != nil {
		return err
	}
	defer wipe(der)
	sealed, sealedType, err := protect(der)
	if err != nil {
		return fmt.Errorf("protect identity key: %w", err)
	}
	block := &pem.Block{
		Type:    sealedType,
		Headers: map[string]string{"Peer-ID": string(i.id)},
		Bytes:   sealed,
	}
	return platform.WriteFileAtomic(path, pem.EncodeToMemory(block), 0o600)
}

// ErrNoIdentity is returned by Load when no identity file exists.
var ErrNoIdentity = errors.New("no identity key found")

// Load reads an identity previously written by Save.
func Load(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("identity file %s is not PEM encoded", path)
	}
	der, err := unprotect(block.Type, block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unlock identity key: %w", err)
	}
	defer wipe(der)
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse identity key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity key is %T, expected Ed25519", key)
	}
	id := FromPrivateKey(priv)
	if want := block.Headers["Peer-ID"]; want != "" && want != string(id.id) {
		return nil, fmt.Errorf("identity file is inconsistent: header peer id %s does not match key", want)
	}
	return id, nil
}

// LoadOrCreate loads the identity at path or generates and saves a new one.
func LoadOrCreate(path string) (id *Identity, created bool, err error) {
	id, err = Load(path)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, ErrNoIdentity) {
		return nil, false, err
	}
	id, err = Generate()
	if err != nil {
		return nil, false, err
	}
	if err := id.Save(path); err != nil {
		return nil, false, fmt.Errorf("save identity: %w", err)
	}
	return id, true, nil
}

// PairingCommit returns the commitment to a pairing nonce, as hex.
func PairingCommit(nonce []byte) string {
	h := sha256.New()
	h.Write([]byte("LANChat pairing commit v1"))
	h.Write(nonce)
	return hex.EncodeToString(h.Sum(nil))
}

// SAS computes the six-digit short authentication string shown to both users
// during pairing. It binds both public keys, the TLS exporter secret of the
// session, and the two pairing nonces exchanged with commit-then-reveal.
// Because the initiator commits to its nonce before seeing the responder's,
// and the responder chooses its nonce before seeing the initiator's, a
// man-in-the-middle cannot steer the codes on two sessions to match; each
// attempt succeeds with probability 10^-6 and costs a visible pairing request.
func SAS(spkiA, spkiB, exporter, initiatorNonce, responderNonce []byte) string {
	a, b := spkiA, spkiB
	if string(b) < string(a) {
		a, b = b, a
	}
	h := sha256.New()
	h.Write([]byte("LANChat SAS v2"))
	var l [4]byte
	for _, part := range [][]byte{a, b, exporter, initiatorNonce, responderNonce} {
		binary.BigEndian.PutUint32(l[:], uint32(len(part)))
		h.Write(l[:])
		h.Write(part)
	}
	sum := h.Sum(nil)
	n := binary.BigEndian.Uint64(sum[:8]) % 1_000_000
	return fmt.Sprintf("%03d %03d", n/1000, n%1000)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
