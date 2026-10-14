package control

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/token"
)

const stateFile = "state.json"

// state is the control plane's durable record. In M0 it is a single JSON file
// on one control node; the Raft-replicated store replaces it later in M0.
type state struct {
	Cluster   string                     `json:"cluster"`
	Address   string                     `json:"address"`    // control plane host:port
	GossipKey []byte                     `json:"gossip_key"` // shared AES-256 gossip key
	Tokens    map[string]*token.Record   `json:"tokens"`
	Members   map[string]*cluster.Member `json:"members"`
}

func loadState(dir string) (*state, error) {
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Tokens == nil {
		s.Tokens = map[string]*token.Record{}
	}
	if s.Members == nil {
		s.Members = map[string]*cluster.Member{}
	}
	return &s, nil
}

// save writes the state atomically: a crash leaves the old or the new file,
// never half of one.
func (s *state) save(dir string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, stateFile+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, stateFile))
}
