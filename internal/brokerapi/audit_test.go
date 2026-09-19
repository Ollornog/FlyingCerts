package brokerapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestFileAuditorWritesOneLinePerEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := NewFileAuditor(path)
	if err != nil {
		t.Fatalf("NewFileAuditor: %v", err)
	}
	defer a.Close()

	a.Record(Event{At: time.Now().UTC(), Action: "fetch", Agent: "gateway", Allowed: true})
	a.Record(Event{At: time.Now().UTC(), Action: "fetch", Agent: "storage", Allowed: false, Reason: "not permitted"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

// Events must be on disk as they happen — buffering would lose exactly the
// ones written just before a crash.
func TestEventsAreVisibleImmediately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := NewFileAuditor(path)
	defer a.Close()

	a.Record(Event{At: time.Now().UTC(), Action: "enrol", Agent: "gateway", Allowed: true})

	// Read without closing: the event has to be there already.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "gateway") {
		t.Error("the event is not on disk before Close")
	}
}

func TestAuditLogIsOwnerReadableOnly(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := NewFileAuditor(path)
	if err != nil {
		t.Fatalf("NewFileAuditor: %v", err)
	}
	defer a.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600 — the log maps the installation", got)
	}
}

func TestFileAuditorIsConcurrencySafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := NewFileAuditor(path)
	defer a.Close()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				a.Record(Event{At: time.Now().UTC(), Action: "fetch", Agent: "gateway", Allowed: true})
			}
		}()
	}
	wg.Wait()

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 32*20 {
		t.Errorf("got %d lines, want %d — concurrent writes lost or interleaved", len(lines), 32*20)
	}
	for _, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("a line was written torn: %v", err)
		}
	}
}

func TestAppendsToAnExistingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	first, _ := NewFileAuditor(path)
	first.Record(Event{At: time.Now().UTC(), Action: "enrol", Agent: "one"})
	_ = first.Close()

	second, _ := NewFileAuditor(path)
	second.Record(Event{At: time.Now().UTC(), Action: "enrol", Agent: "two"})
	_ = second.Close()

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "one") {
		t.Error("reopening the log truncated the history")
	}
	if !strings.Contains(string(data), "two") {
		t.Error("the second event is missing")
	}
}
