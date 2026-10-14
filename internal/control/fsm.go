package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/hashicorp/raft"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/token"
)

// ControlInfo is one control node: its Raft identity and addresses.
type ControlInfo struct {
	ID       string `json:"id"`
	APIAddr  string `json:"api_addr"`
	RaftAddr string `json:"raft_addr"`
}

// state is the replicated control-plane record. Every control node holds a
// full copy; Raft keeps them identical.
type state struct {
	Cluster   string                     `json:"cluster"`
	GossipKey []byte                     `json:"gossip_key"`
	Tokens    map[string]*token.Record   `json:"tokens"`
	Members   map[string]*cluster.Member `json:"members"`
	Controls  map[string]*ControlInfo    `json:"controls"`
}

func newState() *state {
	return &state{
		Tokens:   map[string]*token.Record{},
		Members:  map[string]*cluster.Member{},
		Controls: map[string]*ControlInfo{},
	}
}

// Command operations. Apply must be deterministic: anything time- or
// randomness-dependent is decided by the leader and carried in the command.
const (
	opInit        = "init"
	opPutToken    = "put_token"
	opAdmit       = "admit"
	opPruneTokens = "prune_tokens"
	opPutControl  = "put_control"
	opDelControl  = "del_control"
)

type command struct {
	Op        string          `json:"op"`
	Cluster   string          `json:"cluster,omitempty"`
	GossipKey []byte          `json:"gossip_key,omitempty"`
	Token     *token.Record   `json:"token,omitempty"`
	TokenID   string          `json:"token_id,omitempty"`
	Member    *cluster.Member `json:"member,omitempty"`
	Control   *ControlInfo    `json:"control,omitempty"`
	Now       time.Time       `json:"now,omitempty"`
}

// Errors the state machine can return for a command.
var (
	errAlreadyInit = errors.New("control: cluster already initialised")
	errTokenGone   = errors.New("control: token no longer valid")
	errDuplicate   = errors.New("control: node id or mesh address already in use")
	errUnknownOp   = errors.New("control: unknown command")
)

type fsm struct {
	mu sync.RWMutex
	st *state
}

func newFSM() *fsm { return &fsm{st: newState()} }

// view runs f with a read lock on the current state.
func (f *fsm) view(fn func(*state)) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	fn(f.st)
}

func (f *fsm) Apply(l *raft.Log) interface{} {
	var c command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		return fmt.Errorf("control: bad command: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.apply(c)
}

func (f *fsm) apply(c command) error {
	st := f.st
	switch c.Op {
	case opInit:
		if st.Cluster != "" {
			return errAlreadyInit
		}
		st.Cluster = c.Cluster
		st.GossipKey = c.GossipKey
		if c.Control != nil {
			st.Controls[c.Control.ID] = c.Control
		}
	case opPutToken:
		st.Tokens[c.Token.ID] = c.Token
	case opAdmit:
		var rec *token.Record
		if c.TokenID != "" {
			r, ok := st.Tokens[c.TokenID]
			if !ok || (r.MaxUses > 0 && r.Uses >= r.MaxUses) {
				return errTokenGone
			}
			rec = r
		}
		if _, ok := st.Members[c.Member.NodeID]; ok {
			return errDuplicate
		}
		for _, m := range st.Members {
			if m.MeshIP == c.Member.MeshIP {
				return errDuplicate
			}
		}
		if rec != nil {
			rec.Uses++
		}
		st.Members[c.Member.NodeID] = c.Member
	case opPruneTokens:
		for id, r := range st.Tokens {
			if c.Now.After(r.Expires) || (r.MaxUses > 0 && r.Uses >= r.MaxUses) {
				delete(st.Tokens, id)
			}
		}
	case opPutControl:
		st.Controls[c.Control.ID] = c.Control
	case opDelControl:
		delete(st.Controls, c.Control.ID)
	default:
		return errUnknownOp
	}
	return nil
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	b, err := json.Marshal(f.st)
	if err != nil {
		return nil, err
	}
	return snapshot(b), nil
}

func (f *fsm) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	st := newState()
	if err := json.NewDecoder(rc).Decode(st); err != nil {
		return err
	}
	if st.Tokens == nil {
		st.Tokens = map[string]*token.Record{}
	}
	if st.Members == nil {
		st.Members = map[string]*cluster.Member{}
	}
	if st.Controls == nil {
		st.Controls = map[string]*ControlInfo{}
	}
	f.mu.Lock()
	f.st = st
	f.mu.Unlock()
	return nil
}

type snapshot []byte

func (s snapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s snapshot) Release() {}
