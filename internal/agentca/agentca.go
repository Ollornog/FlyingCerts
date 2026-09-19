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
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/atomicfile"
	"github.com/Ollornog/FlyingCerts/internal/lifetime"
)

// DefaultAgentLifetime is how long an agent's identity is valid when nothing
// says otherwise.
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
		Subject:      pkix.Name{CommonName: "FlyingCerts agent CA"},
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
// The expiry comes back with the certificate rather than being left for the
// caller to recompute. Two places would otherwise work out the same date from
// the same inputs, and they would disagree the moment one of them forgot the
// CA's own expiry — or that "unlimited" is not a duration to add to now.
func SignAgent(ca *CA, agentName string, csr *x509.CertificateRequest, span lifetime.Span) ([]byte, time.Time, error) {
	if agentName == "" {
		return nil, time.Time{}, errors.New("no agent name")
	}
	if csr == nil {
		return nil, time.Time{}, errors.New("no certificate request")
	}
	// The CSR proves the asker holds the private key. Skipping this check
	// would let anyone enrol with someone else's public key.
	if err := csr.CheckSignature(); err != nil {
		return nil, time.Time{}, fmt.Errorf("certificate request is not correctly signed: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	now := time.Now().UTC()
	notAfter, err := agentNotAfter(ca, span, now)
	if err != nil {
		return nil, time.Time{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// The identity is the name, and nothing else: no DNS names, no IPs.
		// This certificate is never used to serve anything.
		Subject:               pkix.Name{CommonName: agentName},
		NotBefore:             now.Add(-time.Minute), // same skew tolerance as the token check
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("sign agent certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), notAfter, nil
}

// agentNotAfter works out when an identity stops working.
//
// Three cases, kept apart on purpose:
//
//   - unset: the package default, deliberately short.
//   - a duration: exactly that, and an error when it would outlive the CA.
//     Silently shortening a lifetime somebody wrote down would mean the
//     configuration says one thing and the certificate another.
//   - unlimited: the CA's own expiry. There is no such thing as a certificate
//     that never expires, so this is as close as the format allows — and the
//     honest way to say it, rather than picking a number that looks infinite.
func agentNotAfter(ca *CA, span lifetime.Span, now time.Time) (time.Time, error) {
	caEnd := ca.cert.NotAfter
	if !now.Before(caEnd) {
		return time.Time{}, fmt.Errorf("the agent CA expired on %s; no identity can be issued from it",
			caEnd.UTC().Format(time.RFC3339))
	}
	if span.IsUnlimited() {
		return caEnd, nil
	}
	d := span.Duration()
	if !span.Set() || d <= 0 {
		d = DefaultAgentLifetime
	}
	// Truncated to the second, which is all X.509 stores. Returning a more
	// precise time than the certificate carries would make the recorded
	// expiry and the real one differ by a fraction — invisible, and still a
	// value that claims to be something it is not.
	end := now.Add(d).Truncate(time.Second)
	if end.After(caEnd) {
		// Checked against the CA's real expiry, not against the span it was
		// created with: a CA issued years ago has less left than its nominal
		// lifetime, and an identity that outlives its issuer stops working
		// without anything in the logs saying why.
		return time.Time{}, fmt.Errorf(
			"a lifetime of %s outlives the agent CA, which expires on %s — "+
				"shorten it, or use %s to mean exactly that",
			span, caEnd.UTC().Format("2006-01-02"), lifetime.Unlimited)
	}
	return end, nil
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

// SignServer issues the broker's own TLS certificate.
//
// The broker needs one that agents can verify, and the only thing an agent is
// given at enrolment is this CA. So the endpoint's certificate comes from
// here — not from the public ACME side, which agents have no reason to trust
// for this purpose and which would tie the endpoint to a public name.
//
// Separate from SignAgent because the two are opposites: an agent identity may
// only authenticate, a server certificate may only serve. Issuing one function
// that does both would eventually hand someone a certificate that does both.
func SignServer(ca *CA, names []string, lifetime time.Duration) (certPEM, keyPEM []byte, err error) {
	if len(names) == 0 {
		return nil, nil, errors.New("no names for the server certificate")
	}
	if lifetime <= 0 {
		lifetime = DefaultAgentLifetime
	}
	if lifetime > rootLifetime {
		return nil, nil, errors.New("requested lifetime outlives the CA")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	var dnsNames []string
	var ips []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, n)
	}

	now := time.Now().UTC()
	// The broker's own certificate is issued by this program, not configured
	// by hand, so shortening it to the CA's expiry is the right thing rather
	// than an error to report to somebody who did not ask for it.
	notAfter := now.Add(lifetime)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign server certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal server key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}
