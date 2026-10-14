package control

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
	"github.com/jibzmat/JunkyardServers/internal/token"
)

// ControlInfo is one control node: its Raft identity and addresses.
type ControlInfo struct {
	ID       string `json:"id"`
	APIAddr  string `json:"api_addr"`
	RaftAddr string `json:"raft_addr"`
	// ShareKey is the X25519 key this node's share of the KEK is sealed to.
	ShareKey []byte `json:"share_key,omitempty"`
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
	Tenants    map[string]*s3meta.Tenant    `json:"tenants"`
	AccessKeys map[string]*s3meta.AccessKey `json:"access_keys"`
	Buckets    map[string]*s3meta.Bucket    `json:"buckets"`
	Objects    map[string]*objectSet        `json:"objects"` // bucket -> key -> object
	Uploads    map[string]*s3meta.Upload    `json:"uploads"` // multipart uploads by ID

	KEK *kekState `json:"kek,omitempty"`

	EC2 ec2State `json:"ec2"`
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
		st.Objects = map[string]*objectSet{}
	}
	if st.Uploads == nil {
		st.Uploads = map[string]*s3meta.Upload{}
	}
	st.EC2.fill()
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

	opCreateUpload   = "create_upload"
	opPutPart        = "put_part"
	opCompleteUpload = "complete_upload"
	opAbortUpload    = "abort_upload"

	opMoveShards = "move_shards"
	opRecode     = "recode_segment"

	opPutKEK      = "put_kek"
	opSetShareKey = "set_share_key"
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

	Upload   *s3meta.Upload         `json:"upload,omitempty"`
	UploadID string                 `json:"upload_id,omitempty"`
	Part     *s3meta.Part           `json:"part,omitempty"`
	Parts    []s3meta.CompletedPart `json:"parts,omitempty"`

	KEK      *kekState         `json:"kek,omitempty"`
	KEKEpoch int               `json:"kek_epoch,omitempty"`
	Sealed   map[string][]byte `json:"sealed,omitempty"` // tenant -> master key sealed by the new KEK

	SegmentID string                `json:"segment_id,omitempty"`
	Moves     []s3meta.ShardMove    `json:"moves,omitempty"`
	EC2       *ec2Command           `json:"ec2,omitempty"`
	Layout    *storage.Layout       `json:"layout,omitempty"`  // recode: the new layout
	OldLayout string                `json:"old_sum,omitempty"` // recode: Sum of the layout replaced
	Audits    []storage.AuditResult `json:"audits,omitempty"`
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
	var res any
	var err error
	switch c.Op {
	case opPutObject, opDeleteObject:
		res, err = f.applyObject(c)
	case opCreateUpload, opPutPart, opCompleteUpload, opAbortUpload:
		res, err = f.applyUpload(c)
	case opMoveShards:
		err = f.applyMoves(c)
	case opRecode:
		err = f.applyRecode(c)
	case opAudits:
		err = f.applyAudits(c)
	case opReinstate:
		err = f.applyReinstate(c)
	case opRunInstances, opInstanceAction, opAssign, opUnassign, opInstanceReport, opPurgeInstances,
		opPutKeyPair, opDeleteKeyPair, opPutImage, opDeleteImage, opTags,
		opCreateVPC, opDeleteVPC, opCreateSubnet, opDeleteSubnet, opCreateGroup, opDeleteGroup, opGroupRules, opDefaultVPC,
		opCreateVolume, opDeleteVolume, opAttachVolume, opDetachVolume, opVolumeReport,
		opCreateSnapshot, opDeleteSnapshot, opCreateImage, opTaskDone, opTaskFailed,
		opSetReplica, opReplicaReport, opFailover, opMoveVolume, opMigrate, opMigrated, opDrain:
		res, err = f.applyEC2(c)
	default:
		return f.apply(c)
	}
	if err != nil {
		return err
	}
	return res
}

// errStale means the object changed since repair read it.
var errStale = errors.New("control: object changed during repair")

// copySegment returns a deep copy of the object named in c and a pointer
// to the layout of segment c.SegmentID within it.
func (f *fsm) copySegment(c command) (*s3meta.Object, *storage.Layout, error) {
	old, ok := f.st.Objects[c.Name].get(c.Key)
	if !ok {
		return nil, nil, errStale
	}
	b, err := json.Marshal(old)
	if err != nil {
		return nil, nil, err
	}
	obj := &s3meta.Object{}
	if err := json.Unmarshal(b, obj); err != nil {
		return nil, nil, err
	}
	var layout *storage.Layout
	if len(obj.Parts) == 0 && obj.ID == c.SegmentID {
		layout = &obj.Layout
	}
	for i := range obj.Parts {
		if obj.Parts[i].ID == c.SegmentID {
			layout = &obj.Parts[i].Layout
		}
	}
	if layout == nil {
		return nil, nil, errStale
	}
	return obj, layout, nil
}

// applyRecode replaces a segment's layout with one using a stronger
// coding, if the layout is still the one the new one was made from.
func (f *fsm) applyRecode(c command) error {
	obj, layout, err := f.copySegment(c)
	if err != nil {
		return err
	}
	if c.Layout == nil || layout.Sum() != c.OldLayout || len(c.Layout.Chunks) != len(layout.Chunks) {
		return errStale
	}
	*layout = *c.Layout
	f.st.Objects[c.Name].set(c.Key, obj)
	return nil
}

// applyMoves records rebuilt shards. Stored objects are never modified in
// place (readers hold shallow copies), so the object is copied first.
func (f *fsm) applyMoves(c command) error {
	obj, layout, err := f.copySegment(c)
	if err != nil {
		return err
	}
	for _, mv := range c.Moves {
		if mv.Chunk < 0 || mv.Chunk >= len(layout.Chunks) || mv.Index < 0 || mv.Index >= layout.DataShards+layout.ParityShards {
			return errStale
		}
		ch := &layout.Chunks[mv.Chunk]
		found := false
		for j := range ch.Shards {
			if ch.Shards[j].Index == mv.Index {
				if ch.Shards[j].Hash != mv.Hash {
					return errStale
				}
				ch.Shards[j].Node = mv.Node
				found = true
			}
		}
		if !found {
			ch.Shards = append(ch.Shards, storage.ShardRef{Index: mv.Index, Hash: mv.Hash, Node: mv.Node})
		}
	}
	f.st.Objects[c.Name].set(c.Key, obj)
	return nil
}

// applyUpload handles multipart uploads.
func (f *fsm) applyUpload(c command) (any, error) {
	st := f.st
	if c.Op == opCreateUpload {
		u := c.Upload
		if b, ok := st.Buckets[u.Bucket]; !ok || b.Tenant != c.Owner {
			return nil, s3meta.Errorf(s3meta.CodeNoSuchBucket, "bucket %q does not exist", u.Bucket)
		}
		u.Tenant = c.Owner
		u.Parts = map[int]*s3meta.Part{}
		st.Uploads[u.ID] = u
		return nil, nil
	}
	u, ok := st.Uploads[c.UploadID]
	if !ok || u.Tenant != c.Owner || u.Bucket != c.Name || u.Key != c.Key {
		return nil, s3meta.Errorf(s3meta.CodeNoSuchUpload, "upload does not exist")
	}
	switch c.Op {
	case opPutPart:
		old := u.Parts[c.Part.Number]
		u.Parts[c.Part.Number] = c.Part
		return old, nil
	case opAbortUpload:
		delete(st.Uploads, u.ID)
		return u, nil
	}

	// Complete: the listed parts must exist, match their ETags, ascend,
	// and all but the last be at least MinPartSize.
	if len(c.Parts) == 0 {
		return nil, s3meta.Errorf(s3meta.CodeInvalidPart, "no parts listed")
	}
	obj := &s3meta.Object{Bucket: u.Bucket, Key: u.Key, ID: u.ID, ContentType: u.ContentType, Metadata: u.Metadata, Modified: c.Now}
	md5s := md5.New()
	used := map[int]bool{}
	for i, cp := range c.Parts {
		if i > 0 && cp.Number <= c.Parts[i-1].Number {
			return nil, s3meta.Errorf(s3meta.CodeInvalidPartOrder, "parts must be listed in ascending order")
		}
		p, ok := u.Parts[cp.Number]
		if !ok || strings.Trim(cp.ETag, `"`) != p.ETag {
			return nil, s3meta.Errorf(s3meta.CodeInvalidPart, "part %d was not uploaded or its ETag differs", cp.Number)
		}
		if i < len(c.Parts)-1 && p.Size < s3meta.MinPartSize {
			return nil, s3meta.Errorf(s3meta.CodeEntityTooSmall, "part %d is smaller than 5 MiB", cp.Number)
		}
		sum, _ := hex.DecodeString(p.ETag)
		md5s.Write(sum)
		obj.Parts = append(obj.Parts, p.Segment)
		obj.Size += p.Size
		used[cp.Number] = true
	}
	obj.ETag = fmt.Sprintf("%s-%d", hex.EncodeToString(md5s.Sum(nil)), len(c.Parts))
	resp := &s3meta.CompleteUploadResponse{Object: obj}
	for n, p := range u.Parts {
		if !used[n] {
			resp.Discard = append(resp.Discard, p.Segment)
		}
	}
	b, ok := st.Buckets[u.Bucket]
	if !ok || b.Tenant != c.Owner {
		return nil, s3meta.Errorf(s3meta.CodeNoSuchBucket, "bucket %q does not exist", u.Bucket)
	}
	objs := st.Objects[u.Bucket]
	if objs == nil {
		objs = newObjectSet()
		st.Objects[u.Bucket] = objs
	}
	resp.Old, _ = objs.get(u.Key)
	objs.set(u.Key, obj)
	delete(st.Uploads, u.ID)
	return resp, nil
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
		objs = newObjectSet()
		st.Objects[name] = objs
	}
	old, _ := objs.get(key)
	if c.Op == opPutObject {
		objs.set(key, c.Object)
	} else {
		objs.del(key)
	}
	return old, nil
}

func (f *fsm) apply(c command) error {
	st := f.st
	switch c.Op {
	case opPutKEK:
		cur := 0
		if st.KEK != nil {
			cur = st.KEK.Epoch
		}
		if c.KEK.Epoch != cur+1 || len(c.Sealed) != len(st.Tenants) {
			return errStaleKEK
		}
		for name := range st.Tenants {
			if _, ok := c.Sealed[name]; !ok {
				return errStaleKEK
			}
		}
		for name, t := range st.Tenants {
			cp := *t
			cp.SealedKey, cp.MasterKey = c.Sealed[name], nil
			st.Tenants[name] = &cp
		}
		st.KEK = c.KEK
	case opSetShareKey:
		old, ok := st.Controls[c.Control.ID]
		if !ok {
			return errors.New("control: unknown control node")
		}
		cp := *old
		cp.ShareKey = c.Control.ShareKey
		st.Controls[cp.ID] = &cp
	case opPutTenant:
		if st.KEK == nil || c.KEKEpoch != st.KEK.Epoch {
			return errStaleKEK
		}
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
		if st.Objects[c.Name].len() > 0 {
			return s3meta.Errorf(s3meta.CodeBucketNotEmpty, "bucket %q is not empty", c.Name)
		}
		for _, u := range st.Uploads {
			if u.Bucket == c.Name {
				return s3meta.Errorf(s3meta.CodeBucketNotEmpty, "bucket %q has multipart uploads in progress", c.Name)
			}
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
