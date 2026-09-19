// Package agent is the side that runs on the internal host: it enrols once,
// then asks the broker for its certificates and puts them where the local
// service will find them.
package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Ollornog/flying-certs/internal/atomicfile"
	"github.com/Ollornog/flying-certs/internal/certinfo"
)

// ErrNotEnrolled reports that this host has no identity yet.
var ErrNotEnrolled = errors.New("this host is not enrolled")

// ErrIdentityExpired reports an identity that can no longer authenticate.
//
// Its own error because it needs its own answer: there is no way back through
// renewal (ADR-7), the host must be enrolled again. Reporting this as a
// generic connection failure would send someone hunting the network instead.
var ErrIdentityExpired = errors.New("the identity has expired and cannot renew itself")

// Identity is this host's client certificate and key.
type Identity struct {
	dir string

	Certificate *x509.Certificate
	certPEM     []byte
	keyPEM      []byte
	caPEM       []byte
}

// paths inside the identity directory.
func certPath(dir string) string { return filepath.Join(dir, "agent.crt") }
func keyPath(dir string) string  { return filepath.Join(dir, "agent.key") }
func caPath(dir string) string   { return filepath.Join(dir, "broker-ca.crt") }

// LoadIdentity reads the stored identity.
func LoadIdentity(dir string) (*Identity, error) {
	certPEM, err := os.ReadFile(certPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, fmt.Errorf("read identity certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath(dir))
	if err != nil {
		// A certificate without its key cannot authenticate. Not
		// ErrNotEnrolled: something is there and broken, and enrolling again
		// over the top would hide that.
		return nil, fmt.Errorf("identity certificate exists but its key does not: %w", err)
	}
	caPEM, err := os.ReadFile(caPath(dir))
	if err != nil {
		return nil, fmt.Errorf("read the broker's CA certificate: %w", err)
	}

	pair, err := certinfo.LoadPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("stored identity is unusable: %w", err)
	}
	return &Identity{dir: dir, Certificate: pair.Leaf, certPEM: certPEM, keyPEM: keyPEM, caPEM: caPEM}, nil
}

// Name is the agent name the broker assigned.
func (i *Identity) Name() string { return i.Certificate.Subject.CommonName }

// ExpiredAt reports whether the identity can still authenticate.
func (i *Identity) ExpiredAt(now time.Time) bool { return certinfo.ExpiredAt(i.Certificate, now) }

// NeedsRenewalAt reports whether it is time to renew.
//
// Two thirds of the lifetime, the same fraction used for server certificates.
// With a 30-day identity that leaves ten days of slack — enough for a host to
// be off over a holiday without locking itself out.
func (i *Identity) NeedsRenewalAt(now time.Time) bool {
	return certinfo.NeedsRenewalAt(i.Certificate, now, certinfo.DefaultRenewalFraction)
}

// TLSConfig builds the client configuration for talking to the broker.
func (i *Identity) TLSConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(i.certPEM, i.keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load identity as a TLS certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(i.caPEM) {
		return nil, errors.New("the stored broker CA certificate is not usable")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// The broker is verified against the CA it gave us at enrolment, not
		// against the system trust store. That is the point of the mutual
		// arrangement: neither side accepts a stranger.
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// NewKeyAndCSR generates a key and a certificate request for this host.
//
// The key is generated here and written here. It never goes anywhere — that
// is the whole reason the broker asks for a CSR rather than handing out keys.
func NewKeyAndCSR(commonName string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate request: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// NewCSRForNames generates a key and a request covering exactly names.
//
// Exactly, because the broker compares the set and refuses anything else —
// asking for less is as wrong as asking for more (see internal/csrcheck).
func NewCSRForNames(names []string) (keyPEM, csrPEM []byte, err error) {
	if len(names) == 0 {
		return nil, nil, errors.New("no names to request")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: names[0]},
		DNSNames: names,
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate request: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// SaveIdentity stores a freshly issued identity.
func SaveIdentity(dir string, certPEM, keyPEM, caPEM []byte) (*Identity, error) {
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

	// Key first, then certificate: a stale key alone is harmless, a new
	// certificate without its key looks complete and fails at the handshake.
	if err := atomicfile.WriteSecret(keyPath(dir), keyPEM); err != nil {
		return nil, fmt.Errorf("write identity key: %w", err)
	}
	if err := atomicfile.WritePublic(certPath(dir), certPEM); err != nil {
		return nil, fmt.Errorf("write identity certificate: %w", err)
	}
	if len(caPEM) > 0 {
		if err := atomicfile.WritePublic(caPath(dir), caPEM); err != nil {
			return nil, fmt.Errorf("write the broker's CA certificate: %w", err)
		}
	}
	return LoadIdentity(dir)
}
