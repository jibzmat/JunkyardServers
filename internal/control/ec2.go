package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// EC2 metadata: instances, key pairs and images live in the Raft state.
// The leader schedules pending instances onto compute hosts; each host
// polls for its instances, runs them and reports their state.

// Image bytes are stored as objects in a bucket no tenant can name (S3
// bucket names can't contain '_'), so repair, re-coding and garbage
// collection cover them like any other object.
const (
	imageBucket = "_images"
	systemOwner = "_system"
)

// How long finished things linger, and how long a host may be silent.
const (
	terminatedLinger = time.Hour
	hostLostAfter    = 2 * time.Minute
)

// EC2 command operations.
const (
	opRunInstances   = "run_instances"
	opInstanceAction = "instance_action" // stop, start, terminate, reboot
	opAssign         = "assign_instance"
	opUnassign       = "unassign_instance"
	opInstanceReport = "instance_report"
	opPurgeInstances = "purge_instances"
	opPutKeyPair     = "put_key_pair"
	opDeleteKeyPair  = "delete_key_pair"
	opPutImage       = "put_image"
	opDeleteImage    = "delete_image"
	opTags           = "tags"
)

type ec2Command struct {
	Instances []ec2meta.Instance     `json:"instances,omitempty"`
	IDs       []string               `json:"ids,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Host      string                 `json:"host,omitempty"`
	IP        string                 `json:"ip,omitempty"`
	MAC       string                 `json:"mac,omitempty"`
	Report    *ec2meta.StatusReport  `json:"report,omitempty"`
	KeyPair   *ec2meta.KeyPair       `json:"key_pair,omitempty"`
	Volume    *ec2meta.Volume        `json:"volume,omitempty"`
	Snapshot  *ec2meta.Snapshot      `json:"snapshot,omitempty"`
	Task      *ec2meta.Task          `json:"task,omitempty"`
	Attach    *ec2meta.AttachRequest `json:"attach,omitempty"`
	VolReport *ec2meta.VolumeReport  `json:"vol_report,omitempty"`
	Failure   *ec2meta.TaskFailure   `json:"failure,omitempty"`
	Image     *ec2meta.Image         `json:"image,omitempty"`
	Object    *s3meta.Object         `json:"object,omitempty"`
	Tags      *ec2meta.TagsRequest   `json:"tags,omitempty"`
	Net       *vpcCommand            `json:"net,omitempty"`
	// Target is the replica host for set_replica.
	Target        string                 `json:"target,omitempty"`
	ReplicaReport *ec2meta.ReplicaReport `json:"replica_report,omitempty"`
}

// ec2State is the EC2 part of the replicated state.
type ec2State struct {
	Instances map[string]*ec2meta.Instance      `json:"instances"`
	KeyPairs  map[string]*ec2meta.KeyPair       `json:"key_pairs"` // tenant + "/" + name
	Images    map[string]*ec2meta.Image         `json:"images"`
	Volumes   map[string]*ec2meta.Volume        `json:"volumes"`
	Snapshots map[string]*ec2meta.Snapshot      `json:"snapshots"`
	Tasks     map[string]*ec2meta.Task          `json:"tasks"`
	VPCs      map[string]*ec2meta.VPC           `json:"vpcs"`
	Subnets   map[string]*ec2meta.Subnet        `json:"subnets"`
	Groups    map[string]*ec2meta.SecurityGroup `json:"groups"`
	// NextVNI is the next VXLAN identifier to give a VPC.
	NextVNI uint32 `json:"next_vni"`
}

func (e *ec2State) fill() {
	if e.Instances == nil {
		e.Instances = map[string]*ec2meta.Instance{}
	}
	if e.KeyPairs == nil {
		e.KeyPairs = map[string]*ec2meta.KeyPair{}
	}
	if e.Images == nil {
		e.Images = map[string]*ec2meta.Image{}
	}
	if e.Volumes == nil {
		e.Volumes = map[string]*ec2meta.Volume{}
	}
	if e.Snapshots == nil {
		e.Snapshots = map[string]*ec2meta.Snapshot{}
	}
	if e.Tasks == nil {
		e.Tasks = map[string]*ec2meta.Task{}
	}
	if e.VPCs == nil {
		e.VPCs = map[string]*ec2meta.VPC{}
	}
	if e.Subnets == nil {
		e.Subnets = map[string]*ec2meta.Subnet{}
	}
	if e.Groups == nil {
		e.Groups = map[string]*ec2meta.SecurityGroup{}
	}
}

func errCode(code, format string, args ...any) error {
	return s3meta.Errorf(code, format, args...)
}

// applyEC2 runs an EC2 command. Records are replaced, never modified in
// place, because readers keep shallow copies.
func (f *fsm) applyEC2(c command) (any, error) {
	e := &f.st.EC2
	x := c.EC2
	if x == nil {
		return nil, errors.New("control: missing ec2 command")
	}
	if res, ok, err := f.applyVPC(c); ok {
		return res, err
	}
	if res, ok, err := f.applyReplica(c); ok {
		return res, err
	}
	switch c.Op {
	case opRunInstances:
		if len(x.Instances) == 0 {
			return nil, errCode(ec2meta.CodeInvalidParameter, "no instances")
		}
		if img, ok := e.Images[x.Instances[0].ImageID]; !ok || !(img.Tenant == c.Owner || img.Public) || !img.Available() {
			return nil, errCode(ec2meta.CodeInvalidAMIID, "image %s does not exist", x.Instances[0].ImageID)
		}
		first := x.Instances[0]
		sn, ok := e.Subnets[first.SubnetID]
		if !ok || sn.Tenant != c.Owner {
			return nil, errCode(ec2meta.CodeSubnetNotFound, "the subnet ID '%s' does not exist", first.SubnetID)
		}
		if len(first.SecurityGroups) == 0 {
			return nil, errCode(ec2meta.CodeInvalidParameter, "no security groups")
		}
		for _, id := range first.SecurityGroups {
			if g, ok := e.Groups[id]; !ok || g.Tenant != c.Owner || g.VpcID != sn.VpcID {
				return nil, errCode(ec2meta.CodeGroupNotFound, "the security group '%s' does not exist in VPC '%s'", id, sn.VpcID)
			}
		}
		taken := map[string]bool{}
		var out []ec2meta.Instance
		for i := range x.Instances {
			in := x.Instances[i]
			if _, ok := e.Instances[in.ID]; ok {
				return nil, fmt.Errorf("control: instance %s exists", in.ID)
			}
			ip, err := instanceIP(e, sn, taken)
			if err != nil {
				return nil, err
			}
			taken[ip] = true
			in.Tenant, in.State, in.Changed = c.Owner, ec2meta.StatePending, c.Now
			in.VpcID, in.SubnetID, in.SecurityGroups = sn.VpcID, sn.ID, first.SecurityGroups
			in.PrivateIP, in.MAC = ip, macFor(in.ID)
			out = append(out, in)
		}
		for i := range out {
			in := out[i]
			e.Instances[in.ID] = &in
		}
		return out, nil

	case opInstanceAction:
		var resp ec2meta.ChangeResponse
		next := map[string]*ec2meta.Instance{}
		for _, id := range x.IDs {
			in, ok := e.Instances[id]
			if !ok || in.Tenant != c.Owner {
				return nil, errCode(ec2meta.CodeInvalidInstanceID, "the instance ID '%s' does not exist", id)
			}
			n := *in
			if err := instanceAction(&n, x.Action, c.Now); err != nil {
				return nil, err
			}
			next[id] = &n
			resp.Changes = append(resp.Changes, ec2meta.StateChange{ID: id, Previous: in.State, Current: n.State})
		}
		for id, n := range next {
			e.Instances[id] = n
		}
		return resp, nil

	case opAssign:
		in, ok := e.Instances[x.IDs[0]]
		if !ok || in.State != ec2meta.StatePending || in.Host != "" {
			return nil, errStale
		}
		if _, ok := f.st.Members[x.Host]; !ok {
			return nil, errStale
		}
		n := *in
		n.Host, n.StateReason = x.Host, ""
		e.Instances[n.ID] = &n
		return n, nil

	case opUnassign:
		in, ok := e.Instances[x.IDs[0]]
		if !ok || in.Host != x.Host {
			return nil, errStale
		}
		n := *in
		switch n.State {
		case ec2meta.StatePending:
			n.Host, n.StateReason = "", x.Action
			detachAll(e, n.ID) // its volumes stay on the lost PC
		case ec2meta.StateShuttingDown:
			n.State, n.Changed, n.StateReason = ec2meta.StateTerminated, c.Now, x.Action
			detachAll(e, n.ID)
		case ec2meta.StateStopping:
			n.State, n.Changed, n.StateReason = ec2meta.StateStopped, c.Now, x.Action
		default:
			return nil, errStale
		}
		e.Instances[n.ID] = &n
		return nil, nil

	case opInstanceReport:
		r := x.Report
		in, ok := e.Instances[r.ID]
		if !ok || in.Host != x.Host {
			return nil, errStale
		}
		n := *in
		if !hostTransition(n.State, r.State) {
			return nil, errStale
		}
		if n.State != r.State {
			n.State, n.Changed = r.State, c.Now
		}
		n.StateReason = r.Reason
		e.Instances[n.ID] = &n
		if n.State == ec2meta.StateTerminated {
			detachAll(e, n.ID)
		}
		return nil, nil

	case opPurgeInstances:
		for _, id := range x.IDs {
			if in, ok := e.Instances[id]; ok && in.State == ec2meta.StateTerminated {
				delete(e.Instances, id)
			}
		}
		return nil, nil

	case opPutKeyPair:
		k := x.KeyPair
		id := c.Owner + "/" + k.Name
		if _, ok := e.KeyPairs[id]; ok {
			return nil, errCode(ec2meta.CodeKeyPairDuplicate, "the keypair '%s' already exists", k.Name)
		}
		kp := *k
		kp.Tenant = c.Owner
		e.KeyPairs[id] = &kp
		return nil, nil

	case opDeleteKeyPair:
		delete(e.KeyPairs, c.Owner+"/"+x.KeyPair.Name)
		return nil, nil

	case opPutImage:
		img := *x.Image
		if _, ok := e.Images[img.ID]; ok {
			return nil, fmt.Errorf("control: image %s exists", img.ID)
		}
		img.Tenant = c.Owner
		e.Images[img.ID] = &img
		if f.st.Buckets[imageBucket] == nil {
			f.st.Buckets[imageBucket] = &s3meta.Bucket{Name: imageBucket, Tenant: systemOwner, Created: c.Now}
		}
		objs := f.st.Objects[imageBucket]
		if objs == nil {
			objs = newObjectSet()
			f.st.Objects[imageBucket] = objs
		}
		obj := *x.Object
		obj.Bucket, obj.Key, obj.Modified = imageBucket, img.ID, c.Now
		objs.set(img.ID, &obj)
		return nil, nil

	case opDeleteImage:
		img, ok := e.Images[x.Image.ID]
		if !ok || img.Tenant != c.Owner {
			return nil, errCode(ec2meta.CodeInvalidAMIID, "the image id '[%s]' does not exist", x.Image.ID)
		}
		delete(e.Images, img.ID)
		for id, t := range e.Tasks {
			if t.Target == img.ID {
				delete(e.Tasks, id)
			}
		}
		old, _ := f.st.Objects[imageBucket].get(img.ID)
		f.st.Objects[imageBucket].del(img.ID)
		return old, nil

	case opTags:
		t := x.Tags
		for _, id := range t.Resources {
			if !hasResource(e, c.Owner, id) {
				return nil, errCode(ec2meta.CodeInvalidParameter, "resource %s does not exist", id)
			}
		}
		for _, id := range t.Resources {
			setTags(e, c.Owner, id, t.Tags, t.Delete)
		}
		return nil, nil
	}
	return f.applyEC2Storage(c)
}

// instanceAction applies a tenant's stop, start, terminate or reboot.
func instanceAction(n *ec2meta.Instance, action string, now time.Time) error {
	set := func(s string) {
		if n.State != s {
			n.State, n.Changed, n.StateReason = s, now, ""
		}
	}
	bad := func() error {
		return errCode(ec2meta.CodeIncorrectState, "the instance '%s' is not in a state from which it can be %s", n.ID, action)
	}
	switch action {
	case "terminate":
		switch n.State {
		case ec2meta.StateTerminated, ec2meta.StateShuttingDown:
		case ec2meta.StatePending, ec2meta.StateStopped:
			if n.Host == "" {
				set(ec2meta.StateTerminated)
			} else {
				set(ec2meta.StateShuttingDown)
			}
		default:
			set(ec2meta.StateShuttingDown)
		}
	case "stop":
		switch n.State {
		case ec2meta.StateStopped, ec2meta.StateStopping:
		case ec2meta.StateRunning, ec2meta.StatePending:
			if n.Host == "" {
				set(ec2meta.StateStopped)
			} else {
				set(ec2meta.StateStopping)
			}
		default:
			return bad()
		}
	case "start":
		switch n.State {
		case ec2meta.StateRunning, ec2meta.StatePending:
		case ec2meta.StateStopped:
			set(ec2meta.StatePending)
		default:
			return bad()
		}
	case "reboot":
		if n.State != ec2meta.StateRunning {
			return bad()
		}
		n.RebootSeq++
	default:
		return fmt.Errorf("control: unknown instance action %q", action)
	}
	return nil
}

// hostTransition says which state changes a host may report.
func hostTransition(from, to string) bool {
	switch from {
	case ec2meta.StatePending:
		return to == ec2meta.StateRunning || to == ec2meta.StatePending || to == ec2meta.StateStopped
	case ec2meta.StateRunning:
		return to == ec2meta.StateRunning || to == ec2meta.StateStopped // shut down from inside
	case ec2meta.StateStopping:
		return to == ec2meta.StateStopped
	case ec2meta.StateShuttingDown:
		return to == ec2meta.StateTerminated
	}
	return false
}

func hasResource(e *ec2State, tenant, id string) bool {
	switch {
	case strings.HasPrefix(id, "i-"):
		in, ok := e.Instances[id]
		return ok && in.Tenant == tenant
	case strings.HasPrefix(id, "ami-"):
		img, ok := e.Images[id]
		return ok && img.Tenant == tenant
	case strings.HasPrefix(id, "key-"):
		for _, k := range e.KeyPairs {
			if k.ID == id && k.Tenant == tenant {
				return true
			}
		}
	case strings.HasPrefix(id, "vol-"):
		v, ok := e.Volumes[id]
		return ok && v.Tenant == tenant
	case strings.HasPrefix(id, "snap-"):
		sn, ok := e.Snapshots[id]
		return ok && sn.Tenant == tenant
	case strings.HasPrefix(id, "vpc-"):
		v, ok := e.VPCs[id]
		return ok && v.Tenant == tenant
	case strings.HasPrefix(id, "subnet-"):
		v, ok := e.Subnets[id]
		return ok && v.Tenant == tenant
	case strings.HasPrefix(id, "sg-"):
		v, ok := e.Groups[id]
		return ok && v.Tenant == tenant
	}
	return false
}

func mergeTags(old, add map[string]string, del bool) map[string]string {
	out := map[string]string{}
	for k, v := range old {
		out[k] = v
	}
	for k, v := range add {
		if del {
			// EC2 deletes a tag only if the value matches, or none is given.
			if v == "" || out[k] == v {
				delete(out, k)
			}
		} else {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func setTags(e *ec2State, tenant, id string, tags map[string]string, del bool) {
	switch {
	case strings.HasPrefix(id, "i-"):
		n := *e.Instances[id]
		n.Tags = mergeTags(n.Tags, tags, del)
		e.Instances[id] = &n
	case strings.HasPrefix(id, "ami-"):
		n := *e.Images[id]
		n.Tags = mergeTags(n.Tags, tags, del)
		e.Images[id] = &n
	case strings.HasPrefix(id, "vol-"):
		n := *e.Volumes[id]
		n.Tags = mergeTags(n.Tags, tags, del)
		e.Volumes[id] = &n
	case strings.HasPrefix(id, "snap-"):
		n := *e.Snapshots[id]
		n.Tags = mergeTags(n.Tags, tags, del)
		e.Snapshots[id] = &n
	case strings.HasPrefix(id, "vpc-"):
		n := *e.VPCs[id]
		n.Tags = mergeTags(n.Tags, tags, del)
		e.VPCs[id] = &n
	case strings.HasPrefix(id, "subnet-"):
		n := *e.Subnets[id]
		n.Tags = mergeTags(n.Tags, tags, del)
		e.Subnets[id] = &n
	case strings.HasPrefix(id, "sg-"):
		n := *e.Groups[id]
		n.Tags = mergeTags(n.Tags, tags, del)
		e.Groups[id] = &n
	case strings.HasPrefix(id, "key-"):
		for name, k := range e.KeyPairs {
			if k.ID == id && k.Tenant == tenant {
				n := *k
				n.Tags = mergeTags(n.Tags, tags, del)
				e.KeyPairs[name] = &n
			}
		}
	}
}

// --- Server methods (called by the gateway through the client) ---

func (s *Server) ec2Apply(op, tenant string, x ec2Command) (any, error) {
	return s.applyResult(command{Op: op, Owner: tenant, Now: s.now().UTC(), EC2: &x})
}

// RunInstances validates a launch and records the instances as pending.
func (s *Server) RunInstances(tenant string, req ec2meta.RunRequest) (*ec2meta.RunResponse, error) {
	t := req.Template
	if req.Count < 1 || req.Count > 20 {
		return nil, errCode(ec2meta.CodeInvalidParameter, "instance count must be 1 to 20")
	}
	typ, ok := ec2meta.LookupType(t.Type)
	if !ok {
		return nil, errCode(ec2meta.CodeInvalidParameter, "instance type %q is not supported", t.Type)
	}
	if t.Placement == "" {
		t.Placement = ec2meta.PlacementPrivate
	}
	if !ec2meta.ValidPlacement(t.Placement) {
		return nil, errCode(ec2meta.CodeInvalidParameter, "placement must be confidential, private or any")
	}
	if len(t.UserData) > ec2meta.MaxUserData {
		return nil, errCode(ec2meta.CodeInvalidParameter, "user data is limited to 16 KB")
	}
	if t.RootGiB == 0 {
		t.RootGiB = ec2meta.DefaultRootGiB
	}
	if t.RootGiB < 1 || t.RootGiB > 2048 {
		return nil, errCode(ec2meta.CodeInvalidParameter, "root volume must be 1 to 2048 GiB")
	}
	t.VCPU, t.MemMiB = typ.VCPU, typ.MemMiB
	if t.SubnetID == "" {
		if _, err := s.DefaultVPC(tenant); err != nil {
			return nil, err
		}
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.leaderBarrier(); err != nil {
		return nil, err
	}
	var err error
	var existing []ec2meta.Instance
	s.fsm.view(func(st *state) {
		img, ok := st.EC2.Images[t.ImageID]
		if !ok || !(img.Tenant == tenant || img.Public) {
			err = errCode(ec2meta.CodeInvalidAMIID, "the image id '[%s]' does not exist", t.ImageID)
			return
		}
		if !img.Available() {
			err = errCode("InvalidAMIID.Unavailable", "the image %s is %s", t.ImageID, img.StateName())
			return
		}
		if t.KeyName != "" {
			k, ok := st.EC2.KeyPairs[tenant+"/"+t.KeyName]
			if !ok {
				err = errCode(ec2meta.CodeKeyPairNotFound, "the key pair '%s' does not exist", t.KeyName)
				return
			}
			t.PublicKey = k.PublicKey
		}
		if t.ClientToken != "" {
			for _, in := range st.EC2.Instances {
				if in.Tenant == tenant && in.ClientToken == t.ClientToken {
					existing = append(existing, *in)
				}
			}
		}
		if t.SubnetID == "" {
			for _, sn := range st.EC2.Subnets {
				if sn.Tenant == tenant && sn.IsDefault {
					t.SubnetID = sn.ID
				}
			}
		}
		sn, ok := st.EC2.Subnets[t.SubnetID]
		if !ok || sn.Tenant != tenant {
			err = errCode(ec2meta.CodeSubnetNotFound, "the subnet ID '%s' does not exist", t.SubnetID)
			return
		}
		if len(t.SecurityGroups) == 0 {
			for _, g := range st.EC2.Groups {
				if g.VpcID == sn.VpcID && g.Name == ec2meta.DefaultGroupName {
					t.SecurityGroups = []string{g.ID}
				}
			}
		}
		if len(t.SecurityGroups) > 5 {
			err = errCode("SecurityGroupsPerInstanceLimitExceeded", "at most 5 security groups per instance")
			return
		}
		if !s.anyHostCouldRun(st, t) {
			err = errCode(ec2meta.CodeInsufficientCap, "no compute host can run a %s instance with placement %s", t.Type, t.Placement)
		}
	})
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 { // an idempotent retry
		sort.Slice(existing, func(i, j int) bool { return existing[i].LaunchIndex < existing[j].LaunchIndex })
		return &ec2meta.RunResponse{Instances: existing}, nil
	}
	res, err := randString("r-", hexDigits, 17)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	var ins []ec2meta.Instance
	for i := 0; i < req.Count; i++ {
		in := t
		if in.ID, err = randString("i-", hexDigits, 17); err != nil {
			return nil, err
		}
		in.ReservationID, in.LaunchIndex, in.Launched = res, i, now
		in.Host, in.PrivateIP, in.MAC, in.RebootSeq = "", "", "", 0
		ins = append(ins, in)
	}
	out, err := s.ec2Apply(opRunInstances, tenant, ec2Command{Instances: ins})
	if err != nil {
		return nil, err
	}
	ins = out.([]ec2meta.Instance)
	s.kickScheduler()
	return &ec2meta.RunResponse{Instances: ins}, nil
}

const hexDigits = "0123456789abcdef"

// Instances returns a tenant's instances (all, or those named), sorted by
// launch time. Naming an unknown instance is an error.
func (s *Server) Instances(req ec2meta.InstancesRequest) ([]ec2meta.Instance, error) {
	var out []ec2meta.Instance
	var err error
	s.fsm.view(func(st *state) {
		if len(req.IDs) > 0 {
			for _, id := range req.IDs {
				in, ok := st.EC2.Instances[id]
				if !ok || in.Tenant != req.Tenant {
					err = errCode(ec2meta.CodeInvalidInstanceID, "the instance ID '%s' does not exist", id)
					return
				}
				out = append(out, *in)
			}
			return
		}
		for _, in := range st.EC2.Instances {
			if in.Tenant == req.Tenant {
				out = append(out, *in)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Launched.Equal(out[j].Launched) {
			return out[i].Launched.Before(out[j].Launched)
		}
		if out[i].ReservationID != out[j].ReservationID {
			return out[i].ReservationID < out[j].ReservationID
		}
		return out[i].LaunchIndex < out[j].LaunchIndex
	})
	return out, nil
}

// InstanceAction stops, starts, reboots or terminates instances.
func (s *Server) InstanceAction(tenant, action string, ids []string) (*ec2meta.ChangeResponse, error) {
	if len(ids) == 0 {
		return nil, errCode(ec2meta.CodeInvalidParameter, "no instance IDs given")
	}
	res, err := s.ec2Apply(opInstanceAction, tenant, ec2Command{IDs: ids, Action: action})
	if err != nil {
		return nil, err
	}
	s.kickScheduler()
	resp := res.(ec2meta.ChangeResponse)
	return &resp, nil
}

// PutKeyPair registers a key pair.
func (s *Server) PutKeyPair(tenant string, k ec2meta.KeyPair) error {
	if k.Name == "" || len(k.Name) > 255 || k.PublicKey == "" {
		return errCode(ec2meta.CodeInvalidParameter, "a key pair needs a name of 1 to 255 characters and a public key")
	}
	k.Created = s.now().UTC()
	var err error
	if k.ID, err = randString("key-", hexDigits, 17); err != nil {
		return err
	}
	_, err = s.ec2Apply(opPutKeyPair, tenant, ec2Command{KeyPair: &k})
	return err
}

// DeleteKeyPair removes a key pair; deleting a missing one is not an error.
func (s *Server) DeleteKeyPair(tenant, name string) error {
	_, err := s.ec2Apply(opDeleteKeyPair, tenant, ec2Command{KeyPair: &ec2meta.KeyPair{Name: name}})
	return err
}

// KeyPairs returns a tenant's key pairs (all, or those named), by name.
func (s *Server) KeyPairs(req ec2meta.KeyPairRequest) ([]ec2meta.KeyPair, error) {
	var out []ec2meta.KeyPair
	var err error
	s.fsm.view(func(st *state) {
		if len(req.Names) > 0 {
			for _, n := range req.Names {
				k, ok := st.EC2.KeyPairs[req.Tenant+"/"+n]
				if !ok {
					err = errCode(ec2meta.CodeKeyPairNotFound, "the key pair '%s' does not exist", n)
					return
				}
				out = append(out, *k)
			}
			return
		}
		for _, k := range st.EC2.KeyPairs {
			if k.Tenant == req.Tenant {
				out = append(out, *k)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// PutImage records an image whose bytes the gateway has already copied
// into obj (any bucket and key; it is stored in the image bucket).
func (s *Server) PutImage(tenant string, img ec2meta.Image, obj s3meta.Object) (*ec2meta.Image, error) {
	if img.Name == "" || len(img.Name) > 128 {
		return nil, errCode(ec2meta.CodeInvalidParameter, "an image needs a name of 1 to 128 characters")
	}
	var err error
	if img.ID, err = randString("ami-", hexDigits, 17); err != nil {
		return nil, err
	}
	img.Created = s.now().UTC()
	if _, err := s.ec2Apply(opPutImage, tenant, ec2Command{Image: &img, Object: &obj}); err != nil {
		return nil, err
	}
	img.Tenant = tenant
	return &img, nil
}

// DeleteImage removes an image and returns the object holding its bytes,
// whose shards the caller deletes.
func (s *Server) DeleteImage(tenant, id string) (*s3meta.Object, error) {
	res, err := s.ec2Apply(opDeleteImage, tenant, ec2Command{Image: &ec2meta.Image{ID: id}})
	if err != nil {
		return nil, err
	}
	obj, _ := res.(*s3meta.Object)
	return obj, nil
}

// Images returns the images a tenant can see (its own and public ones).
func (s *Server) Images(req ec2meta.ImageRequest) ([]ec2meta.Image, error) {
	var out []ec2meta.Image
	var err error
	s.fsm.view(func(st *state) {
		visible := func(img *ec2meta.Image) bool { return img.Tenant == req.Tenant || img.Public }
		if len(req.IDs) > 0 {
			for _, id := range req.IDs {
				img, ok := st.EC2.Images[id]
				if !ok || !visible(img) {
					err = errCode(ec2meta.CodeInvalidAMIID, "the image id '[%s]' does not exist", id)
					return
				}
				out = append(out, *img)
			}
			return
		}
		for _, img := range st.EC2.Images {
			if visible(img) {
				out = append(out, *img)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// Tags adds or removes tags.
func (s *Server) Tags(req ec2meta.TagsRequest) error {
	_, err := s.ec2Apply(opTags, req.Tenant, ec2Command{Tags: &req})
	return err
}

// --- Scheduler ---

// ComputeOptions configures instance scheduling.
type ComputeOptions struct {
	// Alive reports which nodes gossip sees right now. Nil means all.
	Alive func() map[string]bool
	// AllowEmulation lets hosts without KVM run instances (slowly, under
	// QEMU's emulator). For trying things out; never for real use.
	AllowEmulation bool
	// Store reads image bytes for hosts.
	Store *storage.Store
}

// StartCompute starts the scheduler, which runs while this node leads.
func (s *Server) StartCompute(opts ComputeOptions) {
	s.computeMu.Lock()
	s.compute = opts
	s.computeMu.Unlock()
	go s.schedulerLoop()
}

func (s *Server) computeOpts() ComputeOptions {
	s.computeMu.Lock()
	defer s.computeMu.Unlock()
	return s.compute
}

func (s *Server) kickScheduler() {
	select {
	case s.schedKick <- struct{}{}:
	default:
	}
}

func (s *Server) schedulerLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		case <-s.schedKick:
		}
		if s.IsLeader() {
			if err := s.schedule(); err != nil && !errors.Is(err, ErrNotLeader) {
				s.logger.Printf("scheduler: %v", err)
			}
		}
	}
}

// eligible reports whether member m may run instance in, ignoring load.
func (s *Server) eligible(m *cluster.Member, in ec2meta.Instance, emulate bool) bool {
	if !hasRole(m.Roles, cluster.RoleCompute) || (!m.Hardware.KVM && !emulate) {
		return false
	}
	switch in.Placement {
	case ec2meta.PlacementConfidential:
		return m.Tier == cluster.TierConfidential
	case ec2meta.PlacementAny:
		return true
	default:
		return m.Tier == cluster.TierTrusted || m.Tier == cluster.TierConfidential
	}
}

// capacity is what a host offers: vCPUs (overcommitted 4x) and memory
// (all but 1 GiB, for the host itself).
func capacity(m *cluster.Member) (vcpu, memMiB int) {
	return 4 * m.Hardware.Cores, int(m.Hardware.MemBytes>>20) - 1024
}

// usesHost reports whether an instance holds resources on its host.
func usesHost(in *ec2meta.Instance) bool {
	return in.Host != "" && in.State != ec2meta.StateStopped && in.State != ec2meta.StateTerminated
}

func (s *Server) anyHostCouldRun(st *state, in ec2meta.Instance) bool {
	emulate := s.computeOpts().AllowEmulation
	for _, m := range st.Members {
		if v, mem := capacity(m); s.eligible(m, in, emulate) && v >= in.VCPU && mem >= in.MemMiB {
			return true
		}
	}
	return false
}

// schedule places pending instances, gives up on hosts that vanished and
// purges long-terminated instances.
func (s *Server) schedule() error {
	opts := s.computeOpts()
	var alive map[string]bool
	if opts.Alive != nil {
		alive = opts.Alive()
	}
	isAlive := func(id string) bool { return alive == nil || alive[id] }
	now := s.now()

	type assignment struct{ id, host string }
	type unassign struct{ id, host, reason string }
	var assigns []assignment
	var drops []unassign
	var purge []string
	s.fsm.view(func(st *state) {
		usedCPU, usedMem := map[string]int{}, map[string]int{}
		for _, in := range st.EC2.Instances {
			if usesHost(in) {
				usedCPU[in.Host] += in.VCPU
				usedMem[in.Host] += in.MemMiB
			}
		}
		var pending []*ec2meta.Instance
		for _, in := range st.EC2.Instances {
			switch {
			case in.State == ec2meta.StateTerminated && now.Sub(in.Changed) > terminatedLinger:
				purge = append(purge, in.ID)
			case in.Host != "" && !isAlive(in.Host) && now.Sub(in.Changed) > hostLostAfter && !(in.Replica != "" && in.ReplicaSynced) &&
				(in.State == ec2meta.StatePending || in.State == ec2meta.StateShuttingDown || in.State == ec2meta.StateStopping):
				drops = append(drops, unassign{in.ID, in.Host, "Server.InternalError: host unreachable"})
			case in.Host == "" && in.State == ec2meta.StatePending:
				pending = append(pending, in)
			}
		}
		sort.Slice(pending, func(i, j int) bool { return pending[i].Launched.Before(pending[j].Launched) })
		for _, in := range pending {
			best, bestLoad := "", 2.0
			for id, m := range st.Members {
				if !s.eligible(m, *in, opts.AllowEmulation) || !isAlive(id) {
					continue
				}
				cpu, mem := capacity(m)
				if usedCPU[id]+in.VCPU > cpu || usedMem[id]+in.MemMiB > mem {
					continue
				}
				load := float64(usedMem[id]+in.MemMiB) / float64(mem)
				if load < bestLoad || (load == bestLoad && id < best) {
					best, bestLoad = id, load
				}
			}
			if best == "" {
				continue
			}
			usedCPU[best] += in.VCPU
			usedMem[best] += in.MemMiB
			assigns = append(assigns, assignment{in.ID, best})
		}
	})
	for _, a := range assigns {
		if _, err := s.ec2Apply(opAssign, "", ec2Command{IDs: []string{a.id}, Host: a.host}); err != nil && !errors.Is(err, errStale) {
			return err
		}
	}
	for _, d := range drops {
		if _, err := s.ec2Apply(opUnassign, "", ec2Command{IDs: []string{d.id}, Host: d.host, Action: d.reason}); err != nil && !errors.Is(err, errStale) {
			return err
		}
	}
	if len(purge) > 0 {
		if _, err := s.ec2Apply(opPurgeInstances, "", ec2Command{IDs: purge}); err != nil {
			return err
		}
		s.dropConsoles(purge)
	}
	if err := s.scheduleReplicas(alive, now); err != nil {
		return err
	}
	return s.failLostTasks(isAlive)
}

// macFor derives a locally administered MAC address from an instance ID.
func macFor(id string) string {
	h := sha256.Sum256([]byte(id))
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3], h[4])
}

// --- Host API ---

// HostView returns what a compute host should be running.
func (s *Server) HostView(host string) ec2meta.HostView {
	var v ec2meta.HostView
	v.Node = host
	s.fsm.view(func(st *state) {
		if m, ok := st.Members[host]; ok {
			v.MeshIP = m.MeshIP
		}
		vpcs := map[string]bool{}
		for _, in := range st.EC2.Instances {
			if in.Host == host {
				v.Instances = append(v.Instances, *in)
				if in.State != ec2meta.StateTerminated {
					vpcs[in.VpcID] = true
				}
			}
		}
		for id := range vpcs {
			if n, ok := vpcNet(st, id, host); ok {
				v.Networks = append(v.Networks, n)
			}
		}
		for _, vol := range st.EC2.Volumes {
			if vol.Host == host {
				v.Volumes = append(v.Volumes, *vol)
			}
		}
		for _, t := range st.EC2.Tasks {
			if t.Host == host {
				v.Tasks = append(v.Tasks, *t)
			}
		}
		v.Replicas = replicaDisks(st, host)
	})
	sort.Slice(v.Networks, func(i, j int) bool { return v.Networks[i].VPC.ID < v.Networks[j].VPC.ID })
	sort.Slice(v.Volumes, func(i, j int) bool { return v.Volumes[i].ID < v.Volumes[j].ID })
	sort.Slice(v.Tasks, func(i, j int) bool { return v.Tasks[i].ID < v.Tasks[j].ID })
	sort.Slice(v.Instances, func(i, j int) bool { return v.Instances[i].ID < v.Instances[j].ID })
	return v
}

// ReportInstance records the state a host says an instance is in.
func (s *Server) ReportInstance(host string, r ec2meta.StatusReport) error {
	_, err := s.ec2Apply(opInstanceReport, "", ec2Command{Host: host, Report: &r})
	return err
}

// imageFor checks that host runs an instance of image id and returns the
// image and the object holding its bytes.
func (s *Server) imageFor(host, id string) (*ec2meta.Image, *s3meta.Object, error) {
	var img *ec2meta.Image
	var obj *s3meta.Object
	allowed := false
	s.fsm.view(func(st *state) {
		for _, in := range st.EC2.Instances {
			if in.Host == host && in.ImageID == id && in.State != ec2meta.StateTerminated {
				allowed = true
			}
		}
		if i, ok := st.EC2.Images[id]; ok {
			img = i
			obj, _ = st.Objects[imageBucket].get(id)
		}
	})
	if !allowed || img == nil || obj == nil {
		return nil, nil, errCode(ec2meta.CodeInvalidAMIID, "image %s is not used by this host", id)
	}
	return img, obj, nil
}

// WriteImage writes an image's bytes to w, decrypting with its owner's key.
func (s *Server) WriteImage(ctx context.Context, img *ec2meta.Image, obj *s3meta.Object, w io.Writer) error {
	st := s.computeOpts().Store
	if st == nil {
		return errors.New("control: this node can't read images")
	}
	for _, seg := range obj.Segments() {
		raw, err := s.UnwrapKey(img.Tenant, seg.WrappedKey)
		if err != nil {
			return err
		}
		key, err := storage.ObjectKeyFromBytes(raw)
		if err != nil {
			return err
		}
		if err := st.Get(ctx, seg.ID, key, seg.Layout, 0, -1, w); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) ec2Routes(mux *http.ServeMux) {
	gw := func(h http.HandlerFunc) http.HandlerFunc { return s.requireGateway(s.leaderOnly(h)) }
	mux.HandleFunc("POST /v1/ec2/instances/run", gw(s.handleRunInstances))
	mux.HandleFunc("POST /v1/ec2/instances/list", gw(s.handleInstances))
	mux.HandleFunc("POST /v1/ec2/instances/{action}", gw(s.handleInstanceAction))
	mux.HandleFunc("POST /v1/ec2/key-pairs/put", gw(s.handlePutKeyPair))
	mux.HandleFunc("POST /v1/ec2/key-pairs/delete", gw(s.handleDeleteKeyPair))
	mux.HandleFunc("POST /v1/ec2/key-pairs/list", gw(s.handleKeyPairs))
	mux.HandleFunc("POST /v1/ec2/images/put", gw(s.handlePutImage))
	mux.HandleFunc("POST /v1/ec2/images/delete", gw(s.handleDeleteImage))
	mux.HandleFunc("POST /v1/ec2/images/list", gw(s.handleImages))
	mux.HandleFunc("POST /v1/ec2/tags", gw(s.handleTags))
	mux.HandleFunc("POST /v1/ec2/console", gw(s.handleConsole))

	host := func(h http.HandlerFunc) http.HandlerFunc { return s.requireKind(h, pki.KindNode) }
	mux.HandleFunc("GET /v1/ec2/host", host(s.leaderOnly(s.handleHostView)))
	mux.HandleFunc("POST /v1/ec2/host/console", host(s.leaderOnly(s.handleHostConsole)))
	mux.HandleFunc("POST /v1/ec2/host/report", host(s.leaderOnly(s.handleHostReport)))
	mux.HandleFunc("POST /v1/ec2/host/replica-report", host(s.leaderOnly(s.handleReplicaReport)))
	mux.HandleFunc("GET /v1/ec2/host/images/{id}", host(s.handleHostImage))
}

func certName(r *http.Request) string { return r.TLS.VerifiedChains[0][0].Subject.CommonName }

func (s *Server) handleRunInstances(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tenant string `json:"tenant"`
		ec2meta.RunRequest
	}
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.RunInstances(req.Tenant, req.RunRequest)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.InstancesRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.Instances(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, ec2meta.InstancesResponse{Instances: out})
}

func (s *Server) handleInstanceAction(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.InstancesRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.InstanceAction(req.Tenant, r.PathValue("action"), req.IDs)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handlePutKeyPair(w http.ResponseWriter, r *http.Request) {
	var k ec2meta.KeyPair
	if !decode(w, r, &k) {
		return
	}
	if err := s.PutKeyPair(k.Tenant, k); err != nil {
		metaError(w, err)
		return
	}
	out, err := s.KeyPairs(ec2meta.KeyPairRequest{Tenant: k.Tenant, Names: []string{k.Name}})
	if err != nil || len(out) != 1 {
		metaError(w, err)
		return
	}
	writeJSON(w, out[0])
}

func (s *Server) handleDeleteKeyPair(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.KeyPairRequest
	if !decode(w, r, &req) {
		return
	}
	for _, n := range req.Names {
		if err := s.DeleteKeyPair(req.Tenant, n); err != nil {
			metaError(w, err)
			return
		}
	}
	writeJSON(w, struct{}{})
}

func (s *Server) handleKeyPairs(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.KeyPairRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.KeyPairs(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
}

type putImageRequest struct {
	Image  ec2meta.Image `json:"image"`
	Object s3meta.Object `json:"object"`
}

func (s *Server) handlePutImage(w http.ResponseWriter, r *http.Request) {
	var req putImageRequest
	if !decodeLimit(w, r, &req, maxMetaBodyBytes) {
		return
	}
	img, err := s.PutImage(req.Image.Tenant, req.Image, req.Object)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, img)
}

func (s *Server) handleDeleteImage(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.ImageRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.IDs) != 1 {
		httpError(w, http.StatusBadRequest, "name one image")
		return
	}
	obj, err := s.DeleteImage(req.Tenant, req.IDs[0])
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.ObjectResponse{Object: obj})
}

func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.ImageRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.Images(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.TagsRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.Tags(req); err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}

func (s *Server) handleHostView(w http.ResponseWriter, r *http.Request) {
	if err := s.caughtUp(); err != nil {
		httpError(w, http.StatusServiceUnavailable, "the control plane is catching up; retry")
		return
	}
	writeJSON(w, s.HostView(certName(r)))
}

func (s *Server) handleHostReport(w http.ResponseWriter, r *http.Request) {
	var rep ec2meta.StatusReport
	if !decode(w, r, &rep) {
		return
	}
	if err := s.ReportInstance(certName(r), rep); err != nil {
		if errors.Is(err, errStale) {
			httpError(w, http.StatusConflict, err.Error())
			return
		}
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}

func (s *Server) handleHostImage(w http.ResponseWriter, r *http.Request) {
	img, obj, err := s.imageFor(certName(r), r.PathValue("id"))
	if err != nil {
		metaError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(obj.Size))
	w.Header().Set("X-Image-Format", img.Format)
	if err := s.WriteImage(r.Context(), img, obj, w); err != nil {
		s.logger.Printf("image %s for %s: %v", img.ID, certName(r), err)
	}
}
