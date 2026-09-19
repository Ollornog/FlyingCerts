package backup

import (
	"path/filepath"

	"github.com/Ollornog/FlyingCerts/internal/config"
)

// PathsFor works out where this host keeps each area.
//
// This is the single place the scope is decided. A field added to the
// configuration that holds state and is not listed here would silently fall
// out of every backup — which is exactly how one project shipped backups
// without its own CA key (#409) — so a test walks the configuration struct and
// fails on any field this function has not been taught about.
func PathsFor(cfg *config.Config) Paths {
	p := Paths{
		Dirs:  map[Area]string{},
		Files: map[Area]map[string]string{},
	}
	if cfg.Storage.AccountDir != "" {
		p.Dirs[AreaAccount] = cfg.Storage.AccountDir
	}
	if cfg.Storage.CertificateDir != "" {
		p.Dirs[AreaCertificates] = cfg.Storage.CertificateDir
	}
	if cfg.Broker.StateDir != "" {
		p.Dirs[AreaState] = cfg.Broker.StateDir
	}
	if cfg.Broker.AuditLog != "" {
		p.Files[AreaAudit] = map[string]string{
			filepath.Base(cfg.Broker.AuditLog): cfg.Broker.AuditLog,
		}
	}
	// The endpoint's own pair is normally inside the state directory and so
	// already covered. It is listed separately only when it was configured
	// elsewhere — in which case leaving it out would mean a restored broker
	// that cannot open its own listener.
	if cfg.Broker.ServerCert != "" && cfg.Broker.ServerKey != "" {
		p.Files[AreaServer] = map[string]string{
			"broker.crt": cfg.Broker.ServerCert,
			"broker.key": cfg.Broker.ServerKey,
		}
	}
	return p
}
