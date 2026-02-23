package resume

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// State tracks the progress of a scan so it can be resumed after interruption.
type State struct {
	URL            string   `json:"url"`
	CompletedPaths []string `json:"completed_paths"`
	TotalPaths     int      `json:"total_paths"`

	mu   sync.Mutex
	path string
	done map[string]struct{}
}

// New creates a new empty resume state that will be saved to the given path.
func New(path, url string, totalPaths int) *State {
	return &State{
		URL:        url,
		TotalPaths: totalPaths,
		path:       path,
		done:       make(map[string]struct{}),
	}
}

// Load reads an existing resume state from disk. Returns nil if the file
// does not exist.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading resume file: %w", err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing resume file: %w", err)
	}

	s.path = path
	s.done = make(map[string]struct{}, len(s.CompletedPaths))
	for _, p := range s.CompletedPaths {
		s.done[p] = struct{}{}
	}

	return &s, nil
}

// IsCompleted returns true if the given path was already scanned.
func (s *State) IsCompleted(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.done[path]
	return ok
}

// MarkCompleted records a path as done.
func (s *State) MarkCompleted(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.done[path]; !ok {
		s.done[path] = struct{}{}
		s.CompletedPaths = append(s.CompletedPaths, path)
	}
}

// Save writes the current state to disk.
func (s *State) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("serializing resume state: %w", err)
	}
	return os.WriteFile(s.path, data, 0644)
}

// FilterRemaining returns only paths that haven't been completed yet.
func (s *State) FilterRemaining(paths []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var remaining []string
	for _, p := range paths {
		if _, ok := s.done[p]; !ok {
			remaining = append(remaining, p)
		}
	}
	return remaining
}

// Remove deletes the resume file (called on successful completion).
func (s *State) Remove() error {
	return os.Remove(s.path)
}
