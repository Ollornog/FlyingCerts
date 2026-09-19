// Package agentca issues the certificates agents use to identify themselves.
//
// This is a certificate authority, and that deserves a word, because the
// project says elsewhere that it is not one. Both are true — see ADR-15. There
// are two separate worlds here:
//
//   - The certificates agents install on their services come from a real ACME
//     CA and are trusted by everyone. This package has nothing to do with them.
//   - The certificates agents use to prove who they are come from here, and are
//     trusted by exactly one party: the broker. The root never enters a trust
//     store, is never handed to an agent, and never appears in a delivered
//     bundle.
//
// Mixing the two would be a real accident: an agent that served this root to
// visitors would present a certificate nobody trusts.
package agentca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/Ollornog/flying-certs/internal/atomicfile"
)

// DefaultAgentLifetime is how long an agent's identity is valid.
//
// Short on purpose. Expiry is the sweeping mechanism — a revocation list only
// has to catch the rare compromise, not the everyday case of a host being
// retired. The cost is stated in ADR-7: a host offline longer than this must be
// enrolled again.
const DefaultAgentLifetime = 30 * 24 * time.Hour

// rootLifetime outlives every agent certificate by a wide margin. Rotating the
// root means re-enrolling every agent, so it is not something to do yearly.
const rootLifetime = 10 * 365 * 24 * time.Hour

// ErrNoRoot reports that no CA has been created yet.
var ErrNoRoot = errors.New("no agent CA created")

// CA signs agent identities.
type CA struct {
	dir  string
	cert *x509.Certificate
	key  crypto.Signer
	der  []byte
}

// Open loads the CA from dir, or reports ErrNoRoot when there is none.
func Open(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "agent-ca.crt"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoRoot
	}
	if err != nil {
		return nil, fmt.Errorf("read agent CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "agent-ca.key"))
	if err != nil {
		// A certificate without its key cannot sign. Saying "no CA" here would
		// invite the caller to create a second root and silently invalidate
		// every agent already enrolled under the first.
		return nil, fmt.Errorf("agent CA certificate exists but its key does not: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("agent CA certificate is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse agent CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("agent CA key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse agent CA key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("agent CA key cannot sign")
	}
	return &CA{dir: dir, cert: cert, key: signer, der: block.Bytes}, nil
}

// Create builds a new CA. It refuses when one already exists: a second root
// would leave every enrolled agent holding an identity nobody recognises.
func Create(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", dir, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(dir, perm&^0o077); err != nil {
			return nil, fmt.Errorf("%s is mode %o and could not be narrowed: %w", dir, perm, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-ca.key")); err == nil {
		return nil, fmt.Errorf("an agent CA already exists in %s — creating a second root would "+
			"invalidate every enrolled agent", dir)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "flying-certs agent CA"},
		NotBefore:    now.Add(-time.Hour), // tolerate a little clock skew
		NotAfter:     now.Add(rootLifetime),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// MaxPathLenZero: this root signs leaves and nothing else. Without it
		// a stolen agent key could, in principle, sign further certificates.
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}

	if err := atomicfile.WriteSecret(filepath.Join(dir, "agent-ca.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}
	// The CA certificate itself carries no secret — the broker shows it to
	// agents so they can verify it, and an agent needs it to trust the broker.
	if err := atomicfile.WritePublic(filepath.Join(dir, "agent-ca.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return nil, fmt.Errorf("write CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse freshly created CA certificate: %w", err)
	}
	return &CA{dir: dir, cert: cert, key: key, der: der}, nil
}

// OpenOrCreate loads the CA, creating it on first use.
func OpenOrCreate(dir string) (*CA, error) {
	ca, err := Open(dir)
	if errors.Is(err, ErrNoRoot) {
		return Create(dir)
	}
	return ca, err
}

// SignAgent issues an identity for agentName from its CSR.
//
// Only the name is taken from the request; everything else is set here. A CSR
// is attacker-controlled input, and honouring its extensions would let a host
// ask for a certificate that can sign further ones.
func SignAgent(ca *CA, agentName string, csr *x509.CertificateRequest, lifetime time.Duration) ([]byte, error) {
	if agentName == "" {
		return nil, errors.New("no agent name")
	}
	if csr == nil {
		return nil, errors.New("no certificate request")
	}
	// The CSR proves the asker holds the private key. Skipping this check
	// would let anyone enrol with someone else's public key.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request is not correctly signed: %w", err)
	}
	if lifetime <= 0 {
		lifetime = DefaultAgentLifetime
	}
	if lifetime > rootLifetime {
		return nil, errors.New("requested lifetime outlives the CA")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// The identity is the name, and nothing else: no DNS names, no IPs.
		// This certificate is never used to serve anything.
		Subject:               pkix.Name{CommonName: agentName},
		NotBefore:             now.Add(-time.Minute), // same skew tolerance as the token check
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign agent certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// CertPool returns a pool containing only this CA, for verifying agents.
func (c *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// CertificatePEM is the CA certificate, safe to hand out.
func (c *CA) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// Certificate is the parsed CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// Fingerprint is the SHA-256 of the CA certificate, which a bootstrap token
// binds to so a token cannot be redeemed against a different broker.
func (c *CA) Fingerprint() string { return fingerprint(c.der) }

func randomSerial() (*big.Int, error) {
	// 128 random bits, as the CA/Browser Forum requires of public CAs. Not
	// binding here, but there is no reason to be sloppier than the standard.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}
