package compute

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// hostTask is a task with the volume it snapshots, if any.
type hostTask struct {
	ec2meta.Task
	Volume *ec2meta.Volume
}

// volumePath is absolute: QEMU opens it from its own working directory.
func (h *Host) volumePath(id string) string {
	p := filepath.Join(h.Dir, "volumes", id+".qcow2")
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// volumeWork starts work on volumes that aren't attached (deleting them,
// snapshotting them) and returns the tasks that touch an instance's disks,
// which run with that instance's other work so they don't race it.
func (h *Host) volumeWork(ctx context.Context, v *ec2meta.HostView) map[string][]hostTask {
	vols := map[string]*ec2meta.Volume{}
	for i := range v.Volumes {
		vol := &v.Volumes[i]
		vols[vol.ID] = vol
		if vol.Instance == "" && vol.State == ec2meta.VolumeDeleting {
			h.spawn(ctx, vol.ID, func(ctx context.Context) { h.deleteVolume(ctx, vol.ID) })
		}
	}
	instances := map[string]bool{}
	for _, in := range v.Instances {
		instances[in.ID] = true
	}
	h.mu.Lock()
	live := map[string]bool{}
	for _, t := range v.Tasks {
		live[t.ID] = true
	}
	for id := range h.done {
		if !live[id] {
			delete(h.done, id)
		}
	}
	h.mu.Unlock()

	byInstance := map[string][]hostTask{}
	for _, t := range v.Tasks {
		if h.isDone(t.ID) {
			continue
		}
		ht := hostTask{Task: t, Volume: vols[t.Volume]}
		owner := ""
		switch {
		case t.Kind == ec2meta.TaskImage:
			owner = t.Instance
		case ht.Volume != nil && ht.Volume.Instance != "":
			owner = ht.Volume.Instance
		}
		if owner != "" && instances[owner] {
			byInstance[owner] = append(byInstance[owner], ht)
			continue
		}
		key := t.ID
		if ht.Volume != nil {
			key = ht.Volume.ID
		}
		h.spawn(ctx, key, func(ctx context.Context) { h.runTask(ctx, ht, nil) })
	}
	return byInstance
}

func (h *Host) isDone(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.done[id]
	return ok
}

func (h *Host) reportVolume(ctx context.Context, r ec2meta.VolumeReport) {
	if err := h.Control.ReportVolume(ctx, r); err != nil && ctx.Err() == nil {
		h.logf("compute: reporting volume %s: %v", r.ID, err)
	}
}

// volume returns the path of a volume's data, creating it (blank, or
// restored from its snapshot) on first use.
func (h *Host) volume(ctx context.Context, v ec2meta.Volume) (string, error) {
	h.mu.Lock()
	if h.volumes == nil {
		h.volumes = map[string]*sync.Mutex{}
	}
	l := h.volumes[v.ID]
	if l == nil {
		l = &sync.Mutex{}
		h.volumes[v.ID] = l
	}
	h.mu.Unlock()
	l.Lock()
	defer l.Unlock()

	path := h.volumePath(v.ID)
	if _, err := os.Stat(path); err == nil {
		if !v.Ready {
			h.reportVolume(ctx, ec2meta.VolumeReport{ID: v.ID, Ready: true})
		}
		return path, nil
	}
	if v.Ready {
		// The control plane thinks the data is here, but it's gone (the
		// PC's disk was wiped). Don't hand the guest a blank disk.
		return "", fmt.Errorf("the data of volume %s is missing from this PC", v.ID)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	from := ""
	if v.SnapshotID != "" {
		from = path + ".download"
		f, err := os.Create(from)
		if err != nil {
			return "", err
		}
		defer os.Remove(from)
		h.logf("compute: restoring %s from %s", v.ID, v.SnapshotID)
		err = h.Control.FetchSnapshot(ctx, v.SnapshotID, f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return "", fmt.Errorf("fetching snapshot %s: %w", v.SnapshotID, err)
		}
	}
	tmp := path + ".tmp"
	if err := h.Driver.CreateDisk(ctx, tmp, v.SizeGiB, from); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	h.reportVolume(ctx, ec2meta.VolumeReport{ID: v.ID, Ready: true})
	return path, nil
}

func (h *Host) deleteVolume(ctx context.Context, id string) {
	if err := os.Remove(h.volumePath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		h.logf("compute: deleting volume %s: %v", id, err)
		return
	}
	h.reportVolume(ctx, ec2meta.VolumeReport{ID: id, Deleted: true})
}

// syncVolumes makes a VM's plugged-in volumes match its attachments and
// reports attachments and detachments done. running says whether the VM
// is up; a stopped VM picks its volumes up when it next boots.
func (h *Host) syncVolumes(ctx context.Context, vm *VM, running bool) {
	if len(vm.Volumes) == 0 {
		return
	}
	present := map[string]bool{}
	if running {
		ids, err := h.Driver.Attached(vm)
		if err != nil {
			h.logf("compute: listing volumes of %s: %v", vm.Instance.ID, err)
			return
		}
		for _, id := range ids {
			present[id] = true
		}
	}
	for _, v := range vm.Volumes {
		switch v.AttachState {
		case ec2meta.AttachAttaching, ec2meta.AttachAttached:
			path, err := h.volume(ctx, v)
			if err != nil {
				h.logf("compute: volume %s: %v", v.ID, err)
				continue
			}
			if running && !present[v.ID] {
				if err := h.Driver.Attach(ctx, vm, Disk{ID: v.ID, Path: path}); err != nil {
					h.logf("compute: attaching %s to %s: %v", v.ID, vm.Instance.ID, err)
					continue
				}
			}
			if v.AttachState == ec2meta.AttachAttaching {
				h.reportVolume(ctx, ec2meta.VolumeReport{ID: v.ID, AttachState: ec2meta.AttachAttached})
			}
		case ec2meta.AttachDetaching:
			if running && present[v.ID] {
				if err := h.Driver.Detach(ctx, vm, v.ID); err != nil {
					h.logf("compute: detaching %s from %s: %v", v.ID, vm.Instance.ID, err)
					continue
				}
			}
			h.reportVolume(ctx, ec2meta.VolumeReport{ID: v.ID, AttachState: ec2meta.AttachDetached})
		}
	}
}

// runTask makes an image or snapshot and uploads it, or reports why not.
func (h *Host) runTask(ctx context.Context, t hostTask, vm *VM) {
	if h.isDone(t.ID) {
		return
	}
	err := h.task(ctx, t, vm)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		h.logf("compute: task %s (%s of %s): %v", t.ID, t.Kind, t.Target, err)
		if ferr := h.Control.FailTask(ctx, ec2meta.TaskFailure{ID: t.ID, Reason: firstLine(err.Error())}); ferr != nil {
			h.logf("compute: reporting task %s failed: %v", t.ID, ferr)
			return
		}
	}
	// Remember it so a view that hasn't caught up doesn't run it again.
	h.mu.Lock()
	if h.done == nil {
		h.done = map[string]time.Time{}
	}
	h.done[t.ID] = time.Now()
	h.mu.Unlock()
}

func (h *Host) task(ctx context.Context, t hostTask, vm *VM) error {
	dir := filepath.Join(h.Dir, "tasks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, t.ID+".qcow2")
	os.Remove(tmp)
	defer os.Remove(tmp)

	switch t.Kind {
	case ec2meta.TaskImage:
		if vm == nil {
			return errors.New("the instance is no longer on this PC")
		}
		disk := filepath.Join(vm.Dir, "disk.qcow2")
		if _, err := os.Stat(disk); err != nil {
			return fmt.Errorf("the instance has no disk: %w", err)
		}
		h.logf("compute: making image %s from %s", t.Target, vm.Instance.ID)
		if h.Driver.Running(vm) && !t.NoReboot {
			// Shut down first so the file systems are clean, as EC2 does.
			if err := h.Driver.Stop(ctx, vm, true); err != nil {
				return err
			}
			err := h.Driver.Capture(ctx, vm, disk, tmp)
			if serr := h.boot(ctx, vm); serr != nil {
				h.logf("compute: restarting %s after imaging: %v", vm.Instance.ID, serr)
			}
			if err != nil {
				return err
			}
		} else if err := h.Driver.Capture(ctx, vm, disk, tmp); err != nil {
			return err
		}
	case ec2meta.TaskSnapshot:
		if t.Volume == nil {
			return errors.New("the volume is no longer on this PC")
		}
		path := h.volumePath(t.Volume.ID)
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("the volume's data is missing: %w", err)
		}
		h.logf("compute: snapshotting %s to %s", t.Volume.ID, t.Target)
		if err := h.Driver.Capture(ctx, vm, path, tmp); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown task kind %q", t.Kind)
	}
	return h.Control.UploadTask(ctx, t.ID, func() (io.ReadCloser, int64, error) {
		f, err := os.Open(tmp)
		if err != nil {
			return nil, 0, err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, 0, err
		}
		return f, fi.Size(), nil
	})
}
