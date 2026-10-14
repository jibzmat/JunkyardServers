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
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
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

	// S3 metadata.
	Tenants    map[string]*s3meta.Tenant            `json:"tenants"`
	AccessKeys map[string]*s3meta.AccessKey         `json:"access_keys"`
	Buckets    map[string]*s3meta.Bucket            `json:"buckets"`
	Objects    map[string]map[string]*s3meta.Object `json:"objects"` // bucket -> key -> object
}

func newState() *state {
	st := &state{}
	st.fill()
	return st
}

// fill creates any nil maps (after decoding an older snapshot).
func (st *state) fill() {
	if st.Tokens == nil {
		st.Tokens = map[string]*token.Record{}
	}
	if st.Members == nil {
		st.Members = map[string]*cluster.Member{}
	}
	if st.Controls == nil {
		st.Controls = map[string]*ControlInfo{}
	}
	if st.Tenants == nil {
		st.Tenants = map[string]*s3meta.Tenant{}
	}
	if st.AccessKeys == nil {
		st.AccessKeys = map[string]*s3meta.AccessKey{}
	}
	if st.Buckets == nil {
		st.Buckets = map[string]*s3meta.Bucket{}
	}
	if st.Objects == nil {
		st.Objects = map[string]map[string]*s3meta.Object{}
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

	opPutTenant    = "put_tenant"
	opCreateBucket = "create_bucket"
	opDeleteBucket = "delete_bucket"
	opPutObject    = "put_object"
	opDeleteObject = "delete_object"
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

	Tenant    *s3meta.Tenant    `json:"tenant,omitempty"`
	AccessKey *s3meta.AccessKey `json:"access_key,omitempty"`
	Bucket    *s3meta.Bucket    `json:"bucket,omitempty"`
	Object    *s3meta.Object    `json:"object,omitempty"`
	Owner     string            `json:"owner,omitempty"` // tenant making the request
	Name      string            `json:"name,omitempty"`  // bucket name
	Key       string            `json:"key,omitempty"`   // object key
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
	switch c.Op {
	case opPutObject, opDeleteObject:
		old, err := f.applyObject(c)
		if err != nil {
			return err
		}
		return old
	}
	return f.apply(c)
}

// applyObject handles object writes, returning the object replaced or
// deleted (nil if none) so the caller can delete its shards.
func (f *fsm) applyObject(c command) (*s3meta.Object, error) {
	st := f.st
	name, key := c.Name, c.Key
	if c.Op == opPutObject {
		name, key = c.Object.Bucket, c.Object.Key
	}
	b, ok := st.Buckets[name]
	if !ok || b.Tenant != c.Owner {
		return nil, s3meta.Errorf(s3meta.CodeNoSuchBucket, "bucket %q does not exist", name)
	}
	objs := st.Objects[name]
	if objs == nil {
		objs = map[string]*s3meta.Object{}
		st.Objects[name] = objs
	}
	old := objs[key]
	if c.Op == opPutObject {
		objs[key] = c.Object
	} else {
		delete(objs, key)
	}
	return old, nil
}

func (f *fsm) apply(c command) error {
	st := f.st
	switch c.Op {
	case opPutTenant:
		if _, ok := st.Tenants[c.Tenant.Name]; ok {
			return s3meta.Errorf(s3meta.CodeTenantExists, "tenant %q exists", c.Tenant.Name)
		}
		st.Tenants[c.Tenant.Name] = c.Tenant
		st.AccessKeys[c.AccessKey.ID] = c.AccessKey
	case opCreateBucket:
		if b, ok := st.Buckets[c.Bucket.Name]; ok {
			if b.Tenant == c.Bucket.Tenant {
				return s3meta.Errorf(s3meta.CodeBucketExists, "you already own bucket %q", b.Name)
			}
			return s3meta.Errorf(s3meta.CodeBucketTaken, "bucket %q is taken", b.Name)
		}
		if _, ok := st.Tenants[c.Bucket.Tenant]; !ok {
			return s3meta.Errorf(s3meta.CodeInvalidAccessKey, "unknown tenant")
		}
		st.Buckets[c.Bucket.Name] = c.Bucket
	case opDeleteBucket:
		b, ok := st.Buckets[c.Name]
		if !ok || b.Tenant != c.Owner {
			return s3meta.Errorf(s3meta.CodeNoSuchBucket, "bucket %q does not exist", c.Name)
		}
		if len(st.Objects[c.Name]) > 0 {
			return s3meta.Errorf(s3meta.CodeBucketNotEmpty, "bucket %q is not empty", c.Name)
		}
		delete(st.Buckets, c.Name)
		delete(st.Objects, c.Name)
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
	st := &state{}
	if err := json.NewDecoder(rc).Decode(st); err != nil {
		return err
	}
	st.fill()
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
