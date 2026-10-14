package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// Volumes, snapshots and images made from instances. A volume's data
// lives on the compute PC it was first attached on. Snapshots and
// CreateImage are tasks: the PC streams the disk to the control plane,
// which stores it as an object (encrypted, erasure-coded) in a hidden
// bucket, like registered images.

const snapshotBucket = "_snapshots"

// Storage command operations.
const (
	opCreateVolume   = "create_volume"
	opDeleteVolume   = "delete_volume"
	opAttachVolume   = "attach_volume"
	opDetachVolume   = "detach_volume"
	opVolumeReport   = "volume_report"
	opCreateSnapshot = "create_snapshot"
	opDeleteSnapshot = "delete_snapshot"
	opCreateImage    = "create_image"
	opTaskDone       = "task_done"
	opTaskFailed     = "task_failed"
)

// detachAll releases the volumes attached to an instance that is gone.
func detachAll(e *ec2State, instance string) {
	for id, v := range e.Volumes {
		if v.Instance == instance {
			n := *v
			n.Instance, n.Device, n.AttachState, n.AttachTime = "", "", "", time.Time{}
			n.State = ec2meta.VolumeAvailable
			e.Volumes[id] = &n
		}
	}
}

func (f *fsm) putHidden(bucket string, obj s3meta.Object, now time.Time) {
	if f.st.Buckets[bucket] == nil {
		f.st.Buckets[bucket] = &s3meta.Bucket{Name: bucket, Tenant: systemOwner, Created: now}
	}
	objs := f.st.Objects[bucket]
	if objs == nil {
		objs = newObjectSet()
		f.st.Objects[bucket] = objs
	}
	o := obj
	o.Bucket, o.Modified = bucket, now
	objs.set(o.Key, &o)
}

func (f *fsm) applyEC2Storage(c command) (any, error) {
	e := &f.st.EC2
	x := c.EC2
	volume := func(id string) (*ec2meta.Volume, error) {
		v, ok := e.Volumes[id]
		if !ok || v.Tenant != c.Owner {
			return nil, errCode(ec2meta.CodeVolumeNotFound, "the volume '%s' does not exist", id)
		}
		n := *v
		return &n, nil
	}
	switch c.Op {
	case opCreateVolume:
		v := *x.Volume
		if v.SnapshotID != "" {
			s, ok := e.Snapshots[v.SnapshotID]
			if !ok || s.Tenant != c.Owner || s.State != ec2meta.SnapshotCompleted {
				return nil, errCode(ec2meta.CodeSnapshotNotFound, "the snapshot '%s' does not exist", v.SnapshotID)
			}
		}
		v.Tenant, v.State, v.Created = c.Owner, ec2meta.VolumeAvailable, c.Now
		e.Volumes[v.ID] = &v
		return v, nil

	case opDeleteVolume:
		v, err := volume(x.Volume.ID)
		if err != nil {
			return nil, err
		}
		if v.State == ec2meta.VolumeDeleting {
			return nil, nil
		}
		if v.State != ec2meta.VolumeAvailable {
			return nil, errCode(ec2meta.CodeVolumeInUse, "volume %s is attached to %s", v.ID, v.Instance)
		}
		for _, t := range e.Tasks {
			if t.Volume == v.ID {
				return nil, errCode(ec2meta.CodeVolumeInUse, "volume %s has a snapshot in progress", v.ID)
			}
		}
		if v.Host == "" {
			delete(e.Volumes, v.ID)
			return nil, nil
		}
		v.State = ec2meta.VolumeDeleting
		e.Volumes[v.ID] = v
		return nil, nil

	case opAttachVolume:
		a := x.Attach
		v, err := volume(a.Volume)
		if err != nil {
			return nil, err
		}
		in, ok := e.Instances[a.Instance]
		if !ok || in.Tenant != c.Owner {
			return nil, errCode(ec2meta.CodeInvalidInstanceID, "the instance ID '%s' does not exist", a.Instance)
		}
		if v.State != ec2meta.VolumeAvailable {
			return nil, errCode(ec2meta.CodeVolumeInUse, "volume %s is %s", v.ID, v.State)
		}
		switch in.State {
		case ec2meta.StateRunning, ec2meta.StateStopped, ec2meta.StatePending:
		default:
			return nil, errCode(ec2meta.CodeIncorrectState, "instance %s is %s", in.ID, in.State)
		}
		if in.Host == "" {
			return nil, errCode(ec2meta.CodeIncorrectState, "instance %s has not been placed on a PC yet; try again shortly", in.ID)
		}
		if v.Host != "" && v.Host != in.Host {
			return nil, errCode(ec2meta.CodeInvalidParameter, "volume %s is stored on a different PC from instance %s; snapshot it and create a new volume from the snapshot to move it", v.ID, in.ID)
		}
		for _, o := range e.Volumes {
			if o.Instance == in.ID && o.Device == a.Device {
				return nil, errCode(ec2meta.CodeInvalidParameter, "device %s is already in use on %s", a.Device, in.ID)
			}
		}
		v.Host, v.Instance, v.Device = in.Host, in.ID, a.Device
		v.AttachState, v.AttachTime, v.State = ec2meta.AttachAttaching, c.Now, ec2meta.VolumeInUse
		e.Volumes[v.ID] = v
		return *v, nil

	case opDetachVolume:
		a := x.Attach
		v, err := volume(a.Volume)
		if err != nil {
			return nil, err
		}
		if v.Instance == "" || (a.Instance != "" && a.Instance != v.Instance) {
			return nil, errCode(ec2meta.CodeIncorrectState, "volume %s is not attached", v.ID)
		}
		out := *v
		if a.Force || x.Host != "" { // forced, or the PC is gone
			v.Instance, v.Device, v.AttachState, v.AttachTime = "", "", "", time.Time{}
			v.State = ec2meta.VolumeAvailable
			out.AttachState = ec2meta.AttachDetached
		} else {
			v.AttachState = ec2meta.AttachDetaching
			out.AttachState = ec2meta.AttachDetaching
		}
		e.Volumes[v.ID] = v
		return out, nil

	case opVolumeReport:
		r := x.VolReport
		v, ok := e.Volumes[r.ID]
		if !ok || v.Host != x.Host {
			return nil, errStale
		}
		n := *v
		if r.Ready {
			n.Ready = true
		}
		switch {
		case r.Deleted:
			if n.State != ec2meta.VolumeDeleting {
				return nil, errStale
			}
			delete(e.Volumes, n.ID)
			return nil, nil
		case r.AttachState == ec2meta.AttachAttached && n.AttachState == ec2meta.AttachAttaching:
			n.AttachState = ec2meta.AttachAttached
		case r.AttachState == ec2meta.AttachDetached && n.AttachState == ec2meta.AttachDetaching:
			n.Instance, n.Device, n.AttachState, n.AttachTime = "", "", "", time.Time{}
			n.State = ec2meta.VolumeAvailable
		case r.AttachState != "":
			return nil, errStale
		}
		e.Volumes[n.ID] = &n
		return nil, nil

	case opCreateSnapshot:
		s := *x.Snapshot
		v, err := volume(s.VolumeID)
		if err != nil {
			return nil, err
		}
		if v.State == ec2meta.VolumeDeleting {
			return nil, errCode(ec2meta.CodeIncorrectState, "volume %s is being deleted", v.ID)
		}
		if v.Host == "" || !v.Ready {
			return nil, errCode(ec2meta.CodeIncorrectState, "volume %s has no data yet; attach it to an instance first", v.ID)
		}
		s.Tenant, s.State, s.Created, s.SizeGiB = c.Owner, ec2meta.SnapshotPending, c.Now, v.SizeGiB
		e.Snapshots[s.ID] = &s
		t := *x.Task
		t.Kind, t.Tenant, t.Host, t.Volume, t.Target, t.Created = ec2meta.TaskSnapshot, c.Owner, v.Host, v.ID, s.ID, c.Now
		e.Tasks[t.ID] = &t
		return s, nil

	case opDeleteSnapshot:
		s, ok := e.Snapshots[x.Snapshot.ID]
		if !ok || s.Tenant != c.Owner {
			return nil, errCode(ec2meta.CodeSnapshotNotFound, "the snapshot '%s' does not exist", x.Snapshot.ID)
		}
		for _, v := range e.Volumes {
			if v.SnapshotID == s.ID && !v.Ready {
				return nil, errCode("InvalidSnapshot.InUse", "snapshot %s is being restored to volume %s", s.ID, v.ID)
			}
		}
		delete(e.Snapshots, s.ID)
		for id, t := range e.Tasks {
			if t.Target == s.ID {
				delete(e.Tasks, id)
			}
		}
		old, _ := f.st.Objects[snapshotBucket].get(s.ID)
		f.st.Objects[snapshotBucket].del(s.ID)
		return old, nil

	case opCreateImage:
		in, ok := e.Instances[x.Task.Instance]
		if !ok || in.Tenant != c.Owner {
			return nil, errCode(ec2meta.CodeInvalidInstanceID, "the instance ID '%s' does not exist", x.Task.Instance)
		}
		if in.Host == "" || (in.State != ec2meta.StateRunning && in.State != ec2meta.StateStopped) {
			return nil, errCode(ec2meta.CodeIncorrectState, "instance %s is %s; it must be running or stopped", in.ID, in.State)
		}
		img := *x.Image
		img.Tenant, img.State, img.Created, img.SourceInstance = c.Owner, ec2meta.ImagePending, c.Now, in.ID
		e.Images[img.ID] = &img
		t := *x.Task
		t.Kind, t.Tenant, t.Host, t.Target, t.Created = ec2meta.TaskImage, c.Owner, in.Host, img.ID, c.Now
		e.Tasks[t.ID] = &t
		return img, nil

	case opTaskDone:
		t, ok := e.Tasks[x.Task.ID]
		if !ok || t.Host != x.Host {
			return nil, errStale
		}
		obj := *x.Object
		obj.Key = t.Target
		switch t.Kind {
		case ec2meta.TaskImage:
			img, ok := e.Images[t.Target]
			if !ok {
				return nil, errStale
			}
			n := *img
			n.State, n.Size, n.Format = ec2meta.ImageAvailable, obj.Size, "qcow2"
			e.Images[n.ID] = &n
			f.putHidden(imageBucket, obj, c.Now)
		case ec2meta.TaskSnapshot:
			s, ok := e.Snapshots[t.Target]
			if !ok {
				return nil, errStale
			}
			n := *s
			n.State = ec2meta.SnapshotCompleted
			e.Snapshots[n.ID] = &n
			f.putHidden(snapshotBucket, obj, c.Now)
		}
		delete(e.Tasks, t.ID)
		return nil, nil

	case opTaskFailed:
		t, ok := e.Tasks[x.Failure.ID]
		if !ok || (x.Host != "" && t.Host != x.Host) {
			return nil, errStale
		}
		switch t.Kind {
		case ec2meta.TaskImage:
			if img, ok := e.Images[t.Target]; ok {
				n := *img
				n.State, n.Reason = ec2meta.ImageFailed, x.Failure.Reason
				e.Images[n.ID] = &n
			}
		case ec2meta.TaskSnapshot:
			if s, ok := e.Snapshots[t.Target]; ok {
				n := *s
				n.State, n.Reason = ec2meta.SnapshotError, x.Failure.Reason
				e.Snapshots[n.ID] = &n
			}
		}
		delete(e.Tasks, t.ID)
		return nil, nil
	}
	return nil, errUnknownOp
}

// --- Server methods ---

// validDevice accepts EC2 device names: /dev/sd[f-p], /dev/xvd[b-z], /dev/vd[b-z].
func validDevice(d string) bool {
	for _, p := range []string{"/dev/sd", "/dev/xvd", "/dev/vd"} {
		if rest, ok := strings.CutPrefix(d, p); ok && len(rest) == 1 && rest[0] >= 'b' && rest[0] <= 'z' {
			return true
		}
	}
	return false
}

// CreateVolume makes a volume, blank or from a snapshot.
func (s *Server) CreateVolume(tenant string, v ec2meta.Volume) (*ec2meta.Volume, error) {
	if v.SnapshotID != "" {
		var snap *ec2meta.Snapshot
		s.fsm.view(func(st *state) { snap = st.EC2.Snapshots[v.SnapshotID] })
		if snap != nil && v.SizeGiB == 0 {
			v.SizeGiB = snap.SizeGiB
		}
		if snap != nil && v.SizeGiB < snap.SizeGiB {
			return nil, errCode(ec2meta.CodeInvalidParameter, "the volume must be at least the snapshot's %d GiB", snap.SizeGiB)
		}
	}
	if v.SizeGiB < 1 || v.SizeGiB > 16384 {
		return nil, errCode(ec2meta.CodeInvalidParameter, "volume size must be 1 to 16384 GiB")
	}
	if v.Type == "" {
		v.Type = "gp3"
	}
	var err error
	if v.ID, err = randString("vol-", hexDigits, 17); err != nil {
		return nil, err
	}
	res, err := s.ec2Apply(opCreateVolume, tenant, ec2Command{Volume: &v})
	if err != nil {
		return nil, err
	}
	out := res.(ec2meta.Volume)
	return &out, nil
}

// DeleteVolume deletes an unattached volume.
func (s *Server) DeleteVolume(tenant, id string) error {
	_, err := s.ec2Apply(opDeleteVolume, tenant, ec2Command{Volume: &ec2meta.Volume{ID: id}})
	return err
}

// AttachVolume attaches a volume to an instance.
func (s *Server) AttachVolume(req ec2meta.AttachRequest) (*ec2meta.Volume, error) {
	if !validDevice(req.Device) {
		return nil, errCode(ec2meta.CodeInvalidParameter, "device must look like /dev/sdf (b to z)")
	}
	res, err := s.ec2Apply(opAttachVolume, req.Tenant, ec2Command{Attach: &req})
	if err != nil {
		return nil, err
	}
	v := res.(ec2meta.Volume)
	return &v, nil
}

// DetachVolume detaches a volume. With Force, or when the volume's PC is
// gone, it is released at once.
func (s *Server) DetachVolume(req ec2meta.AttachRequest) (*ec2meta.Volume, error) {
	x := ec2Command{Attach: &req}
	if alive := s.computeOpts().Alive; alive != nil {
		var host string
		s.fsm.view(func(st *state) {
			if v, ok := st.EC2.Volumes[req.Volume]; ok {
				host = v.Host
			}
		})
		if a := alive(); a != nil && host != "" && !a[host] {
			x.Host = host // gone: nothing will answer a detach
		}
	}
	res, err := s.ec2Apply(opDetachVolume, req.Tenant, x)
	if err != nil {
		return nil, err
	}
	v := res.(ec2meta.Volume)
	return &v, nil
}

// Volumes lists a tenant's volumes, or the ones named.
func (s *Server) Volumes(req ec2meta.VolumeRequest) ([]ec2meta.Volume, error) {
	var out []ec2meta.Volume
	var err error
	s.fsm.view(func(st *state) {
		if len(req.IDs) > 0 {
			for _, id := range req.IDs {
				v, ok := st.EC2.Volumes[id]
				if !ok || v.Tenant != req.Tenant {
					err = errCode(ec2meta.CodeVolumeNotFound, "the volume '%s' does not exist", id)
					return
				}
				out = append(out, *v)
			}
			return
		}
		for _, v := range st.EC2.Volumes {
			if v.Tenant == req.Tenant {
				out = append(out, *v)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool {
		return out[i].Created.Before(out[j].Created) || (out[i].Created.Equal(out[j].Created) && out[i].ID < out[j].ID)
	})
	return out, err
}

// CreateSnapshot starts a snapshot of a volume.
func (s *Server) CreateSnapshot(tenant, volume, description string, tags map[string]string) (*ec2meta.Snapshot, error) {
	snap := ec2meta.Snapshot{VolumeID: volume, Description: description, Tags: tags}
	var err error
	if snap.ID, err = randString("snap-", hexDigits, 17); err != nil {
		return nil, err
	}
	t := ec2meta.Task{}
	if t.ID, err = randString("task-", hexDigits, 17); err != nil {
		return nil, err
	}
	res, err := s.ec2Apply(opCreateSnapshot, tenant, ec2Command{Snapshot: &snap, Task: &t})
	if err != nil {
		return nil, err
	}
	out := res.(ec2meta.Snapshot)
	return &out, nil
}

// DeleteSnapshot deletes a snapshot and returns the object holding its
// bytes, whose shards the caller deletes.
func (s *Server) DeleteSnapshot(tenant, id string) (*s3meta.Object, error) {
	res, err := s.ec2Apply(opDeleteSnapshot, tenant, ec2Command{Snapshot: &ec2meta.Snapshot{ID: id}})
	if err != nil {
		return nil, err
	}
	obj, _ := res.(*s3meta.Object)
	return obj, nil
}

// Snapshots lists a tenant's snapshots, or the ones named.
func (s *Server) Snapshots(req ec2meta.VolumeRequest) ([]ec2meta.Snapshot, error) {
	var out []ec2meta.Snapshot
	var err error
	s.fsm.view(func(st *state) {
		if len(req.IDs) > 0 {
			for _, id := range req.IDs {
				sn, ok := st.EC2.Snapshots[id]
				if !ok || sn.Tenant != req.Tenant {
					err = errCode(ec2meta.CodeSnapshotNotFound, "the snapshot '%s' does not exist", id)
					return
				}
				out = append(out, *sn)
			}
			return
		}
		for _, sn := range st.EC2.Snapshots {
			if sn.Tenant == req.Tenant {
				out = append(out, *sn)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool {
		return out[i].Created.Before(out[j].Created) || (out[i].Created.Equal(out[j].Created) && out[i].ID < out[j].ID)
	})
	return out, err
}

// CreateImage starts making an image from an instance's root disk.
func (s *Server) CreateImage(req ec2meta.CreateImageRequest) (*ec2meta.Image, error) {
	if req.Name == "" || len(req.Name) > 128 {
		return nil, errCode(ec2meta.CodeInvalidParameter, "an image needs a name of 1 to 128 characters")
	}
	img := ec2meta.Image{Name: req.Name, Description: req.Description, Tags: req.Tags, Format: "qcow2", Location: "instance/" + req.Instance}
	var err error
	if img.ID, err = randString("ami-", hexDigits, 17); err != nil {
		return nil, err
	}
	t := ec2meta.Task{Instance: req.Instance, NoReboot: req.NoReboot}
	if t.ID, err = randString("task-", hexDigits, 17); err != nil {
		return nil, err
	}
	res, err := s.ec2Apply(opCreateImage, req.Tenant, ec2Command{Image: &img, Task: &t})
	if err != nil {
		return nil, err
	}
	out := res.(ec2meta.Image)
	return &out, nil
}

// failLostTasks fails tasks whose PC has been gone a while.
func (s *Server) failLostTasks(isAlive func(string) bool) error {
	now := s.now()
	var lost []string
	s.fsm.view(func(st *state) {
		for _, t := range st.EC2.Tasks {
			if !isAlive(t.Host) && now.Sub(t.Created) > hostLostAfter {
				lost = append(lost, t.ID)
			}
		}
	})
	for _, id := range lost {
		_, err := s.ec2Apply(opTaskFailed, "", ec2Command{Failure: &ec2meta.TaskFailure{ID: id, Reason: "Server.InternalError: the PC holding the disk is unreachable"}})
		if err != nil && !errors.Is(err, errStale) {
			return err
		}
	}
	return nil
}

// storeStream stores r as a new object's bytes, encrypted for tenant.
func (s *Server) storeStream(ctx context.Context, tenant string, r io.Reader) (*s3meta.Object, error) {
	st := s.computeOpts().Store
	if st == nil {
		return nil, errors.New("control: this node can't store data")
	}
	key, err := storage.NewObjectKey()
	if err != nil {
		return nil, err
	}
	id, err := randString("", hexDigits, 32)
	if err != nil {
		return nil, err
	}
	layout, etag, err := st.Put(ctx, id, key, r)
	if err != nil {
		return nil, err
	}
	wrapped, err := s.WrapKey(tenant, key.Bytes())
	if err != nil {
		st.Delete(context.WithoutCancel(ctx), layout)
		return nil, err
	}
	return &s3meta.Object{ID: id, Size: layout.Size(), ETag: etag, WrappedKey: wrapped, Layout: layout}, nil
}

// --- HTTP ---

func (s *Server) ec2StorageRoutes(mux *http.ServeMux) {
	gw := func(h http.HandlerFunc) http.HandlerFunc { return s.requireGateway(s.leaderOnly(h)) }
	mux.HandleFunc("POST /v1/ec2/volumes/create", gw(s.handleCreateVolume))
	mux.HandleFunc("POST /v1/ec2/volumes/delete", gw(s.handleDeleteVolume))
	mux.HandleFunc("POST /v1/ec2/volumes/attach", gw(s.handleAttachVolume))
	mux.HandleFunc("POST /v1/ec2/volumes/detach", gw(s.handleDetachVolume))
	mux.HandleFunc("POST /v1/ec2/volumes/list", gw(s.handleVolumes))
	mux.HandleFunc("POST /v1/ec2/snapshots/create", gw(s.handleCreateSnapshot))
	mux.HandleFunc("POST /v1/ec2/snapshots/delete", gw(s.handleDeleteSnapshot))
	mux.HandleFunc("POST /v1/ec2/snapshots/list", gw(s.handleSnapshots))
	mux.HandleFunc("POST /v1/ec2/images/create", gw(s.handleCreateImage))

	host := func(h http.HandlerFunc) http.HandlerFunc { return s.requireKind(h, pki.KindNode) }
	mux.HandleFunc("POST /v1/ec2/host/volume-report", host(s.leaderOnly(s.handleVolumeReport)))
	mux.HandleFunc("POST /v1/ec2/host/task-failed", host(s.leaderOnly(s.handleTaskFailed)))
	mux.HandleFunc("PUT /v1/ec2/host/tasks/{id}", host(s.leaderOnly(s.handleTaskUpload)))
	mux.HandleFunc("GET /v1/ec2/host/snapshots/{id}", host(s.handleHostSnapshot))
}

func (s *Server) handleCreateVolume(w http.ResponseWriter, r *http.Request) {
	var v ec2meta.Volume
	if !decode(w, r, &v) {
		return
	}
	out, err := s.CreateVolume(v.Tenant, v)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleDeleteVolume(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.VolumeRequest
	if !decode(w, r, &req) {
		return
	}
	for _, id := range req.IDs {
		if err := s.DeleteVolume(req.Tenant, id); err != nil {
			metaError(w, err)
			return
		}
	}
	writeJSON(w, struct{}{})
}

func (s *Server) handleAttachVolume(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.AttachRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.AttachVolume(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleDetachVolume(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.AttachRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.DetachVolume(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleVolumes(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.VolumeRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.Volumes(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
}

type createSnapshotRequest struct {
	Tenant      string            `json:"tenant"`
	Volume      string            `json:"volume"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

func (s *Server) handleCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	var req createSnapshotRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.CreateSnapshot(req.Tenant, req.Volume, req.Description, req.Tags)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.VolumeRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.IDs) != 1 {
		httpError(w, http.StatusBadRequest, "name one snapshot")
		return
	}
	obj, err := s.DeleteSnapshot(req.Tenant, req.IDs[0])
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.ObjectResponse{Object: obj})
}

func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.VolumeRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.Snapshots(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleCreateImage(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.CreateImageRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.CreateImage(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleVolumeReport(w http.ResponseWriter, r *http.Request) {
	var rep ec2meta.VolumeReport
	if !decode(w, r, &rep) {
		return
	}
	if _, err := s.ec2Apply(opVolumeReport, "", ec2Command{Host: certName(r), VolReport: &rep}); err != nil {
		if errors.Is(err, errStale) {
			httpError(w, http.StatusConflict, err.Error())
			return
		}
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}

func (s *Server) handleTaskFailed(w http.ResponseWriter, r *http.Request) {
	var f ec2meta.TaskFailure
	if !decode(w, r, &f) {
		return
	}
	if _, err := s.ec2Apply(opTaskFailed, "", ec2Command{Host: certName(r), Failure: &f}); err != nil {
		if errors.Is(err, errStale) {
			httpError(w, http.StatusConflict, err.Error())
			return
		}
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}

// handleTaskUpload stores the disk a host streams for a task and
// completes the task.
func (s *Server) handleTaskUpload(w http.ResponseWriter, r *http.Request) {
	host, id := certName(r), r.PathValue("id")
	var task *ec2meta.Task
	s.fsm.view(func(st *state) {
		if t, ok := st.EC2.Tasks[id]; ok && t.Host == host {
			c := *t
			task = &c
		}
	})
	if task == nil {
		httpError(w, http.StatusNotFound, "no such task for this host")
		return
	}
	obj, err := s.storeStream(r.Context(), task.Tenant, r.Body)
	if err != nil {
		s.logger.Printf("task %s from %s: %v", id, host, err)
		httpError(w, http.StatusServiceUnavailable, fmt.Sprintf("storing the disk: %v", err))
		return
	}
	if _, err := s.ec2Apply(opTaskDone, "", ec2Command{Host: host, Task: task, Object: obj}); err != nil {
		s.computeOpts().Store.Delete(context.WithoutCancel(r.Context()), obj.Layout)
		if errors.Is(err, errStale) {
			httpError(w, http.StatusConflict, "the task was cancelled")
			return
		}
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}

// handleHostSnapshot streams a snapshot to a host restoring a volume
// from it.
func (s *Server) handleHostSnapshot(w http.ResponseWriter, r *http.Request) {
	host, id := certName(r), r.PathValue("id")
	var snap *ec2meta.Snapshot
	var obj *s3meta.Object
	allowed := false
	s.fsm.view(func(st *state) {
		for _, v := range st.EC2.Volumes {
			if v.Host == host && v.SnapshotID == id {
				allowed = true
			}
		}
		snap = st.EC2.Snapshots[id]
		obj, _ = st.Objects[snapshotBucket].get(id)
	})
	if !allowed || snap == nil || obj == nil {
		httpError(w, http.StatusNotFound, "snapshot not used by this host")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(obj.Size))
	w.Header().Set("X-Image-Format", "qcow2")
	if err := s.WriteImage(r.Context(), &ec2meta.Image{ID: id, Tenant: snap.Tenant}, obj, w); err != nil {
		s.logger.Printf("snapshot %s for %s: %v", id, host, err)
	}
}
