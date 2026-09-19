package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/Ollornog/FlyingCerts/internal/atomicfile"
)

// FileState keeps agent state in one JSON file.
//
// One file rather than one per agent: the state is small, and a single
// atomic write cannot leave half the fleet updated and half not.
type FileState struct{ path string }

// NewFileState stores state at path.
func NewFileState(path string) *FileState { return &FileState{path: path} }

// Load reads the state, treating a missing file as an empty one — that is the
// first run, not a fault.
func (f *FileState) Load() (map[string]*State, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]*State{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.path, err)
	}
	var out map[string]*State
	if err := json.Unmarshal(data, &out); err != nil {
		// Deliberately not "start empty": that would silently un-revoke every
		// shut-out agent the moment the file gets corrupted.
		return nil, fmt.Errorf("parse %s: %w", f.path, err)
	}
	if out == nil {
		out = map[string]*State{}
	}
	return out, nil
}

// Save writes the state atomically.
func (f *FileState) Save(state map[string]*State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent state: %w", err)
	}
	return atomicfile.WriteSecret(f.path, append(data, '\n'))
}
