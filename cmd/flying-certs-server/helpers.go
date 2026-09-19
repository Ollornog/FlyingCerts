package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Ollornog/flying-certs/internal/certinfo"
)

// tlsCertificate is an alias so broker.go reads without importing crypto/tls
// for one type.
type tlsCertificate = tls.Certificate

func loadKeyPair(certPath, keyPath string) (tlsCertificate, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tlsCertificate{}, fmt.Errorf("load %s and %s: %w", certPath, keyPath, err)
	}
	return pair, nil
}

// hostOf extracts the host from a listen address.
//
// A bare ":8443" means every interface, which is no name to put in a
// certificate — the caller then has to say which name to use.
func hostOf(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return strings.TrimSpace(listen)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return ""
	}
	return host
}

// describeRemaining renders a remaining lifetime for a human.
func describeRemaining(d time.Duration) string {
	return certinfo.DescribeRemaining(d)
}

// describeAgo renders how long ago something happened.
func describeAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%.0f min ago", d.Minutes())
	case d < 48*time.Hour:
		return fmt.Sprintf("%.0f h ago", d.Hours())
	default:
		return fmt.Sprintf("%.0f days ago", d.Hours()/24)
	}
}
