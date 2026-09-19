// Package devicekey is the long-lived key a host proves itself with.
//
// It is the answer to the one failure this design otherwise cannot recover
// from: an identity that expires while the host is switched off. The identity
// is short-lived on purpose, and a short-lived credential cannot renew itself
// after it has lapsed — so something that does not lapse has to vouch for the
// host instead (ADR-7 describes the hole, ADR-18 this way out of it).
//
// The shape is deliberately the one everybody already knows: the host keeps a
// private key, the broker is told the matching public key, and that is the
// whole relationship. It is `authorized_keys`, and it works for the same
// reason — the secret never travels, so there is no copy of it anywhere to
// steal. What travels is a signature, and only within a TLS handshake.
//
// Two keys, not one, and that separation is the point:
//
//   - This key is long-lived and used rarely — only to ask for an identity.
//   - The identity is short-lived and used constantly.
//
// A leaked identity is worth a day. Collapsing the two into one key would
// mean the long-lived secret is also the one in daily use, which is most of
// the way back to an API key.
package devicekey

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
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/atomicfile"
	"github.com/Ollornog/FlyingCerts/internal/keyfp"
)

// FileName is what the key is called inside the agent's state directory.
const FileName = "device.key"

// Key is a host's long-lived key pair.
type Key struct {
	signer *ecdsa.PrivateKey
	pem    []byte
}

// Path returns where the key lives for a given state directory.
func Path(dir string) string { return filepath.Join(dir, FileName) }

// Load reads an existing key.
func Load(dir string) (*Key, error) {
	data, err := os.ReadFile(Path(dir))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM", Path(dir))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Path(dir), err)
	}
	signer, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s holds a %T, expected an ECDSA key", Path(dir), parsed)
	}
	return &Key{signer: signer, pem: data}, nil
}

// Create makes a new key and writes it, refusing to replace one.
//
// Refusing matters: overwriting the device key is how a host silently loses
// the only thing that can get it back in, and it would look like success.
func Create(dir string) (*Key, error) {
	if _, err := os.Stat(Path(dir)); err == nil {
		return nil, fmt.Errorf("%s already exists — a host has one device key, "+
			"and replacing it means re-authorising it on the broker", Path(dir))
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := atomicfile.WriteSecret(Path(dir), keyPEM); err != nil {
		return nil, err
	}
	return &Key{signer: signer, pem: keyPEM}, nil
}

// LoadOrCreate is what the agent calls on every run.
func LoadOrCreate(dir string) (*Key, bool, error) {
	k, err := Load(dir)
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	k, err = Create(dir)
	return k, true, err
}

// Fingerprint is what goes into the broker's configuration.
func (k *Key) Fingerprint() (string, error) { return keyfp.Of(k.signer.Public()) }

// ClientCertificate builds the self-signed certificate this key presents in a
// TLS handshake.
//
// The certificate itself carries no authority and is not checked for any: the
// broker looks only at the public key inside it and at whether the handshake
// was signed by the matching private key. It exists because TLS client
// authentication is defined in terms of certificates, not bare keys.
//
// It is minted fresh for each connection and lives an hour, so there is no
// second file to keep, expire or accidentally trust.
func (k *Key) ClientCertificate(agentName string) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.signer.Public(), k.signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	// The parsed certificate, not the template it was built from: a template
	// has no PublicKey field filled in, and Go's TLS stack reads Leaf when it
	// is set. Handing it a Leaf with a nil key is asking for a confusing
	// failure somewhere far from here.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  k.signer,
		Leaf:        leaf,
	}, nil
}
