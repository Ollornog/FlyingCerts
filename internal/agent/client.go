package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout bounds one call to the broker.
const DefaultTimeout = 30 * time.Second

// Client talks to the broker.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewEnrolmentClient builds a client for the one call that happens without an
// identity.
//
// It needs the broker's CA certificate to verify the other side. Without it
// there is nothing to check against, and a first contact that trusts anything
// is a first contact an attacker can answer. Obtaining that certificate out of
// band is the price of the first handshake, and the documentation says so
// rather than offering a convenient "skip verification" flag.
func NewEnrolmentClient(baseURL string, brokerCAPEM []byte, timeout time.Duration) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("no broker address")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(brokerCAPEM) {
		return nil, errors.New("the broker CA certificate could not be read")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// NewClient builds a client that authenticates with an identity.
func NewClient(baseURL string, id *Identity, timeout time.Duration) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("no broker address")
	}
	if id == nil {
		return nil, ErrNotEnrolled
	}
	if id.ExpiredAt(time.Now()) {
		// Stop here rather than let the handshake fail with something
		// unhelpful. The error names the way out, which since ADR-18 is
		// usually the device key rather than a new token.
		return nil, fmt.Errorf("%w (expired %s) — ask for a new one with this host's device key, "+
			"or enrol it again with a token",
			ErrIdentityExpired, id.Certificate.NotAfter.UTC().Format(time.RFC3339))
	}
	tlsCfg, err := id.TLSConfig()
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// NewDeviceClient builds a client that authenticates with the host's device
// key rather than with an identity.
//
// This is the one that works when nothing else does: the device key does not
// expire, so a host that was switched off for longer than its identity lasted
// can still come back on its own (ADR-18). The broker's CA certificate is
// still needed to verify the far end — that requirement never goes away, and
// there is deliberately no flag to skip it.
func NewDeviceClient(baseURL string, brokerCAPEM []byte, clientCert tls.Certificate,
	timeout time.Duration) (*Client, error) {

	if baseURL == "" {
		return nil, errors.New("no broker address")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(brokerCAPEM) {
		return nil, errors.New("the broker CA certificate could not be read")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{clientCert},
				MinVersion:   tls.VersionTLS12,
			}},
		},
	}, nil
}

// RequestIdentity asks for an identity using the device key.
//
// The request carries no name: the broker works out which agent this is from
// the key it just proved possession of. A name in the body would be a name
// chosen by the caller, which is the mistake this whole design avoids.
func (c *Client) RequestIdentity(ctx context.Context, csrPEM string) (*EnrolResult, error) {
	var out EnrolResult
	if err := c.post(ctx, "/v1/identity/request", map[string]string{"csr": csrPEM}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnrolResult is what the broker returns for a redeemed token.
type EnrolResult struct {
	AgentName      string `json:"agent_name"`
	CertificatePEM string `json:"certificate_pem"`
	CAPem          string `json:"ca_pem"`
	NotAfter       string `json:"not_after"`
}

// Enrol redeems a bootstrap token and returns the issued identity.
func (c *Client) Enrol(ctx context.Context, token, csrPEM string) (*EnrolResult, error) {
	var out EnrolResult
	if err := c.post(ctx, "/v1/enroll", map[string]string{"token": token, "csr": csrPEM}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Certificate is a certificate handed over by the broker.
type Certificate struct {
	Name           string   `json:"name"`
	CertificatePEM string   `json:"certificate_pem"`
	PrivateKeyPEM  string   `json:"private_key_pem,omitempty"`
	IssuerPEM      string   `json:"issuer_pem,omitempty"`
	Domains        []string `json:"domains"`
	NotAfter       string   `json:"not_after"`
}

// Fetch collects a stored certificate (the share mode).
func (c *Client) Fetch(ctx context.Context, name string) (*Certificate, error) {
	var out Certificate
	if err := c.get(ctx, "/v1/certificates/"+name, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Issue asks the broker to obtain a certificate for our own request (the
// issue mode). The key stays here; only the request travels.
func (c *Client) Issue(ctx context.Context, name, csrPEM string) (*Certificate, error) {
	var out Certificate
	if err := c.post(ctx, "/v1/certificates/"+name+"/issue", map[string]string{"csr": csrPEM}, &out); err != nil {
		return nil, err
	}
	out.Name = name
	return &out, nil
}

// RenewIdentity asks for a fresh identity while the current one still works.
func (c *Client) RenewIdentity(ctx context.Context, csrPEM string) (string, error) {
	var out struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := c.post(ctx, "/v1/identity/renew", map[string]string{"csr": csrPEM}, &out); err != nil {
		return "", err
	}
	return out.CertificatePEM, nil
}

// Whoami asks the broker what it thinks this agent is.
func (c *Client) Whoami(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.get(ctx, "/v1/whoami", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	enc, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(enc))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read the answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Pass the broker's own wording through. It is written for exactly
		// this reader, and replacing it with "request failed" would throw
		// away the one thing that explains what to do.
		var errBody struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errBody) == nil && errBody.Error != "" {
			return fmt.Errorf("broker refused %s: %s (HTTP %d)", req.URL.Path, errBody.Error, resp.StatusCode)
		}
		return fmt.Errorf("broker refused %s with HTTP %d", req.URL.Path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("the broker's answer could not be read: %w", err)
	}
	return nil
}
