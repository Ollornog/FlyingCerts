package acme

import "sync"

// ZoneLock serialises work that competes for the same DNS challenge record.
//
// With DNS-01 the requester writes a _acme-challenge record. Two orders that
// need the *same* record at the same time overwrite each other, and the CA sees
// a value that does not match what it was told to expect. The usual symptom is
// "already exists and content does not match", with orders hanging.
//
// Cert Warden fought this for a long while (issues #23 and #74): a domain
// ordered together with its wildcard form, or several domains whose challenge
// records are delegated by CNAME to one shared target. It took a rewrite of the
// solving logic, and for the shared-target case it is reportedly still not
// fully solved.
//
// The lesson taken from that: the key must be the *record that will actually be
// written*, not the name that was asked for. Two different names can land on
// one record through delegation, and a lock keyed on the requested name would
// then guard nothing while looking like it does.
type ZoneLock struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewZoneLock returns a ready ZoneLock.
func NewZoneLock() *ZoneLock {
	return &ZoneLock{locks: make(map[string]*sync.Mutex)}
}

// Acquire blocks until nothing else holds this key, and returns the release.
//
// Callers use it as:
//
//	release := zl.Acquire(target)
//	defer release()
//
// Keys are never removed. A deployment has a handful of challenge targets, so
// the map cannot grow in any meaningful way, and dropping entries would need
// reference counting for no benefit.
func (z *ZoneLock) Acquire(key string) (release func()) {
	z.mu.Lock()
	m, ok := z.locks[key]
	if !ok {
		m = &sync.Mutex{}
		z.locks[key] = m
	}
	z.mu.Unlock()

	m.Lock()
	return m.Unlock
}
