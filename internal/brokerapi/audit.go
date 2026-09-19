package brokerapi

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// FileAuditor appends events to a file, one JSON object per line.
//
// Append-only and line-based on purpose: the file can be tailed while the
// broker runs, fed to anything that reads JSON lines, and a truncated last
// line costs one event rather than the whole record.
//
// Every event is flushed as it happens. Buffering would lose exactly the
// events that matter most — those written just before something went wrong.
type FileAuditor struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewFileAuditor opens (and creates) the audit log.
func NewFileAuditor(path string) (*FileAuditor, error) {
	// 0600: the log names agents, addresses and what they collected. That is
	// a map of the installation for anyone who can read it.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	return &FileAuditor{file: f, enc: json.NewEncoder(f)}, nil
}

// Record writes one event.
//
// A failure here is deliberately not propagated: the caller is in the middle
// of answering an agent, and refusing to serve because the log is full would
// turn a full disk into an outage. It is reported on stderr instead, which is
// where a supervisor will see it.
func (a *FileAuditor) Record(e Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.enc.Encode(e); err != nil {
		fmt.Fprintf(os.Stderr, "FlyingCerts: could not write an audit event: %v\n", err)
	}
}

// Close flushes and closes the log.
func (a *FileAuditor) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.file.Close()
}
