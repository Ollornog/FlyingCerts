package acme

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-acme/lego/v5/lego"
)

// DefaultFinalizeTimeout is how long we wait for the CA to finish an order.
//
// lego's own default is 30 seconds, and that is too short for some CAs. When it
// trips, the CA still issues the certificate — lego has simply stopped
// listening. Every retry then pays for another certificate nobody collects.
// A minute and a half is generous for a CA that behaves and still bounded.
const DefaultFinalizeTimeout = 90 * time.Second

// ClientOptions configure a lego client without exposing lego's own types to
// the rest of the program.
type ClientOptions struct {
	// DirectoryURL is the ACME directory to talk to. Empty means Let's Encrypt
	// production, which is deliberately not a default anywhere in this package —
	// callers say where they are going.
	DirectoryURL string

	// FinalizeTimeout bounds one order. Zero means DefaultFinalizeTimeout.
	FinalizeTimeout time.Duration

	// UserAgent identifies this program to the CA.
	UserAgent string

	// HTTPClient replaces the default transport. Needed for a CA behind a
	// proxy, or one whose chain is not in the system trust store — a test CA,
	// for instance.
	HTTPClient *http.Client
}

// newClient builds a fresh lego client for a single piece of work, using the
// account that was passed in.
//
// Fresh client, kept account. Those two are not in tension, although the two
// projects we learned from each got one half right. A reused client carries the
// challenge provider of the previous request with it — a real bug, fixed in
// acme-manager by building a new client each time. But building a new client is
// not a reason to build a new *account*: doing both is what puts acme-proxy
// into the CA's account rate limit and makes its revocations invalid. So: the
// client is cheap and short-lived, the account is loaded and reused.
func newClient(acct *Account, opts ClientOptions) (*lego.Client, error) {
	if acct == nil {
		return nil, fmt.Errorf("no account: refusing to build an ACME client without one")
	}
	if opts.DirectoryURL == "" {
		return nil, fmt.Errorf("no ACME directory URL given")
	}

	config := lego.NewConfig(acct)
	config.CADirURL = opts.DirectoryURL

	timeout := opts.FinalizeTimeout
	if timeout <= 0 {
		timeout = DefaultFinalizeTimeout
	}
	config.Certificate.Timeout = timeout

	if opts.UserAgent != "" {
		config.UserAgent = opts.UserAgent
	}
	if opts.HTTPClient != nil {
		config.HTTPClient = opts.HTTPClient
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}
	return client, nil
}
