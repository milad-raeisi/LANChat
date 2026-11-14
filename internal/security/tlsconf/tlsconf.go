// Package tlsconf builds the TLS 1.3 configurations used between LANChat
// peers and with the managed discovery server.
//
// Peers authenticate each other with self-signed certificates whose public
// key is the peer's persistent Ed25519 identity key. Standard Web PKI chain
// validation is not applicable, so Go's default verification is replaced by
// VerifyPeerCertificate, which requires exactly one well-formed Ed25519
// certificate. Possession of the matching private key is proven by the TLS
// 1.3 CertificateVerify message. Authorization (is this peer trusted?) is a
// separate, application-level decision based on the derived peer ID.
package tlsconf

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// ALPN is the application protocol negotiated between peers.
const ALPN = "lanchat/1"

// ErrBadPeerCertificate is returned for any certificate that is not a single
// valid self-signed Ed25519 certificate.
var ErrBadPeerCertificate = errors.New("peer presented an invalid identity certificate")

// VerifyPeerCertificate validates the raw certificates presented by a peer.
func VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	_, err := parsePeerCert(rawCerts)
	return err
}

func parsePeerCert(rawCerts [][]byte) (ed25519.PublicKey, error) {
	if len(rawCerts) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one certificate, got %d", ErrBadPeerCertificate, len(rawCerts))
	}
	if len(rawCerts[0]) > 16*1024 {
		return nil, fmt.Errorf("%w: certificate too large", ErrBadPeerCertificate)
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadPeerCertificate, err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: key type %T is not Ed25519", ErrBadPeerCertificate, cert.PublicKey)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, fmt.Errorf("%w: certificate is not self-signed by its key: %v", ErrBadPeerCertificate, err)
	}
	return pub, nil
}

// PeerFromState extracts the authenticated peer key and ID from a completed
// TLS connection.
func PeerFromState(st tls.ConnectionState) (ed25519.PublicKey, identity.PeerID, error) {
	if !st.HandshakeComplete {
		return nil, "", errors.New("TLS handshake not complete")
	}
	if st.Version != tls.VersionTLS13 {
		return nil, "", errors.New("TLS 1.3 is required")
	}
	if len(st.PeerCertificates) == 0 {
		return nil, "", ErrBadPeerCertificate
	}
	raw := make([][]byte, len(st.PeerCertificates))
	for i, c := range st.PeerCertificates {
		raw[i] = c.Raw
	}
	pub, err := parsePeerCert(raw)
	if err != nil {
		return nil, "", err
	}
	return pub, identity.IDFromPublicKey(pub), nil
}

func base(id *identity.Identity) (*tls.Config, error) {
	cert, err := id.Certificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{ALPN},
	}, nil
}

// PeerServerConfig returns the listener configuration. Clients must present
// an identity certificate.
func PeerServerConfig(id *identity.Identity) (*tls.Config, error) {
	c, err := base(id)
	if err != nil {
		return nil, err
	}
	c.ClientAuth = tls.RequireAnyClientCert
	c.VerifyPeerCertificate = VerifyPeerCertificate
	return c, nil
}

// PeerClientConfig returns the dialer configuration.
func PeerClientConfig(id *identity.Identity) (*tls.Config, error) {
	c, err := base(id)
	if err != nil {
		return nil, err
	}
	// Chain-of-trust verification does not apply to self-signed identity
	// certificates; VerifyPeerCertificate performs the identity checks and
	// the application authorizes the derived peer ID.
	c.InsecureSkipVerify = true //nolint:gosec // replaced by VerifyPeerCertificate
	c.VerifyPeerCertificate = VerifyPeerCertificate
	c.ServerName = "lanchat"
	return c, nil
}

// DiscoveryClientConfig returns a configuration for connecting to the
// managed discovery server. The server is authenticated either by pinning
// the SHA-256 fingerprint of its certificate public key (SPKI) or with a CA
// bundle. One of the two is required.
func DiscoveryClientConfig(id *identity.Identity, serverName, pinnedFingerprint, caFile string) (*tls.Config, error) {
	cert, err := id.Certificate()
	if err != nil {
		return nil, err
	}
	c := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		ServerName:   serverName,
	}
	switch {
	case pinnedFingerprint != "":
		want := identity.NormalizeFingerprint(pinnedFingerprint)
		c.InsecureSkipVerify = true //nolint:gosec // replaced by SPKI pinning below
		c.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("discovery server sent no certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if got := identity.FingerprintSPKI(leaf.RawSubjectPublicKeyInfo); got != want {
				return fmt.Errorf("discovery server fingerprint mismatch: got %s, expected %s", got, want)
			}
			return nil
		}
	case caFile != "":
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no certificates", caFile)
		}
		c.RootCAs = pool
	default:
		return nil, errors.New("managed discovery requires a pinned server fingerprint or a CA file")
	}
	return c, nil
}

// ExporterLabel is the TLS exporter label used to bind pairing codes to a session.
const ExporterLabel = "EXPORTER-LANChat-SAS-v1"

// PairingExporter returns 32 bytes of keying material bound to the session.
func PairingExporter(st tls.ConnectionState) ([]byte, error) {
	return st.ExportKeyingMaterial(ExporterLabel, nil, 32)
}
