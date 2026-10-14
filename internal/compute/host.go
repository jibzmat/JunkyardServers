// Package compute runs EC2 instances on a compute host. The host polls the
// control plane for the instances assigned to it, makes the local VMs
// match (boot, stop, reboot, destroy) and reports their actual state.
package compute

import (
	"context"
	"errors"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// VM is an instance as this host runs it.
type VM struct {
	Instance ec2meta.Instance
	Subnet   string // the host's instance subnet
	Dir      string // disk, seed, console log, QMP socket, PID file
	// Volumes are the volumes attached, attaching or detaching.
	Volumes []ec2meta.Volume
	// Disks are the volumes to boot with, set by the host before Start.
	Disks []Disk
}

// Disk is a volume's data file on this host.
type Disk struct {
	ID   string
	Path string
}

// Driver runs VMs. QEMU is the real one.
type Driver interface {
	Network(ctx context.Context, subnet netip.Prefix) error
	ConvertImage(ctx context.Context, src, format, dst string) error
	Prepare(ctx context.Context, vm *VM, image string) error
	Start(ctx context.Context, vm *VM) error
	Running(vm *VM) bool
	Stop(ctx context.Context, vm *VM, graceful bool) error
	Reboot(vm *VM) error
	Destroy(ctx context.Context, vm *VM) error

	// CreateDisk makes a volume's data file: blank, or from a snapshot's
	// qcow2 when from is set, grown to sizeGiB.
	CreateDisk(ctx context.Context, path string, sizeGiB int, from string) error
	// Attached lists the volumes plugged into a running VM.
	Attached(vm *VM) ([]string, error)
	// Attach hotplugs a volume into a running VM.
	Attach(ctx context.Context, vm *VM, d Disk) error
	// Detach unplugs a volume; it fails while the guest still holds it.
	Detach(ctx context.Context, vm *VM, id string) error
	// Capture copies a disk to a standalone qcow2. A running VM is paused
	// for the copy, so the data is consistent as of one instant.
	Capture(ctx context.Context, vm *VM, src, dst string) error
}

// Control is what the host needs from the control plane; *control.Client
// implements it.
type Control interface {
	HostView(ctx context.Context) (*ec2meta.HostView, error)
	ReportInstance(ctx context.Context, r ec2meta.StatusReport) error
	FetchImage(ctx context.Context, id string, w io.Writer) (string, error)
	ReportVolume(ctx context.Context, r ec2meta.VolumeReport) error
	FailTask(ctx context.Context, f ec2meta.TaskFailure) error
	UploadTask(ctx context.Context, id string, open func() (io.ReadCloser, int64, error)) error
	FetchSnapshot(ctx context.Context, id string, w io.Writer) error
	SendConsole(ctx context.Context, c ec2meta.ConsoleOutput) error
}

// Host reconciles this PC's VMs with the control plane.
type Host struct {
	Control Control
	Driver  Driver
	Dir     string
	Logger  *log.Logger
	// Metadata serves the instance metadata service (169.254.169.254).
	Metadata bool
	// Region is reported to instances; default us-east-1.
	Region string

	mu       sync.Mutex
	busy     map[string]bool
	failed   map[string]time.Time // instance -> last failed start
	images   map[string]*sync.Mutex
	volumes  map[string]*sync.Mutex
	done     map[string]time.Time // tasks finished here, until the view drops them
	missing  map[string]time.Time // VM dirs not in the view, since when
	consoles map[string]consoleSent
	byIP     map[string]ec2meta.Instance // for the metadata service
	meta     *metadataServer
	subnet   string
	inflight sync.WaitGroup
}

// retryAfter is how long a failed start waits before the next try.
const retryAfter = 30 * time.Second

// destroyAfter is how long a VM must be missing from the view before it is
// destroyed, so one bad view can't wipe a host.
const destroyAfter = time.Minute

func (h *Host) logf(format string, args ...any) {
	if h.Logger != nil {
		h.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Run reconciles every interval until ctx ends.
func (h *Host) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := h.Step(ctx); err != nil && ctx.Err() == nil {
			h.logf("compute: %v", err)
		}
		select {
		case <-ctx.Done():
			h.inflight.Wait()
			return
		case <-t.C:
		}
	}
}

// Wait waits for the work started by earlier Steps.
func (h *Host) Wait() { h.inflight.Wait() }

// Step fetches the host's instances and starts work on each one that
// needs it. Slow work (downloading an image, a graceful shutdown) runs in
// the background so other instances aren't held up.
func (h *Host) Step(ctx context.Context) error {
	v, err := h.Control.HostView(ctx)
	if err != nil {
		return err
	}
	if v.Subnet != "" && v.Subnet != h.currentSubnet() {
		p, err := netip.ParsePrefix(v.Subnet)
		if err != nil {
			return err
		}
		if err := h.Driver.Network(ctx, p); err != nil {
			return err
		}
		if h.Metadata {
			if err := h.startMetadata(ctx, p); err != nil {
				return err
			}
		}
		h.mu.Lock()
		h.subnet = v.Subnet
		h.mu.Unlock()
	}
	byIP := map[string]ec2meta.Instance{}
	for _, in := range v.Instances {
		if in.PrivateIP != "" && in.State != ec2meta.StateTerminated {
			byIP[in.PrivateIP] = in
		}
	}
	h.mu.Lock()
	h.byIP = byIP
	h.mu.Unlock()
	attached := map[string][]ec2meta.Volume{}
	for _, vol := range v.Volumes {
		if vol.Instance != "" {
			attached[vol.Instance] = append(attached[vol.Instance], vol)
		}
	}
	tasks := h.volumeWork(ctx, v)
	assigned := map[string]bool{}
	for _, in := range v.Instances {
		assigned[in.ID] = true
		vm := &VM{Instance: in, Subnet: v.Subnet, Dir: h.instanceDir(in.ID), Volumes: attached[in.ID]}
		todo := tasks[in.ID]
		h.spawn(ctx, in.ID, func(ctx context.Context) {
			h.reconcile(ctx, vm)
			for _, t := range todo {
				h.runTask(ctx, t, vm)
			}
			h.sendConsole(ctx, vm)
		})
	}
	// VMs no longer assigned here (purged, or moved off a host thought
	// lost) are destroyed.
	entries, _ := os.ReadDir(filepath.Join(h.Dir, "instances"))
	h.mu.Lock()
	if h.missing == nil {
		h.missing = map[string]time.Time{}
	}
	seen := map[string]bool{}
	var gone []string
	for _, e := range entries {
		id := e.Name()
		if assigned[id] || !strings.HasPrefix(id, "i-") {
			continue
		}
		seen[id] = true
		if since, ok := h.missing[id]; !ok {
			h.missing[id] = time.Now()
		} else if time.Since(since) >= destroyAfter {
			gone = append(gone, id)
		}
	}
	for id := range h.missing {
		if !seen[id] {
			delete(h.missing, id)
		}
	}
	h.mu.Unlock()
	for _, id := range gone {
		vm := &VM{Instance: ec2meta.Instance{ID: id}, Dir: h.instanceDir(id)}
		h.spawn(ctx, id, func(ctx context.Context) { h.destroy(ctx, vm) })
	}
	return nil
}

func (h *Host) currentSubnet() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.subnet
}

func (h *Host) instanceDir(id string) string { return filepath.Join(h.Dir, "instances", id) }

// spawn runs fn for an instance unless work on it is already running.
func (h *Host) spawn(ctx context.Context, id string, fn func(context.Context)) {
	h.mu.Lock()
	if h.busy == nil {
		h.busy = map[string]bool{}
	}
	if h.busy[id] {
		h.mu.Unlock()
		return
	}
	h.busy[id] = true
	h.mu.Unlock()
	h.inflight.Add(1)
	go func() {
		defer h.inflight.Done()
		defer func() {
			h.mu.Lock()
			delete(h.busy, id)
			h.mu.Unlock()
		}()
		fn(ctx)
	}()
}

func (h *Host) report(ctx context.Context, id, state, reason string) {
	err := h.Control.ReportInstance(ctx, ec2meta.StatusReport{ID: id, State: state, Reason: reason})
	if err != nil && ctx.Err() == nil {
		h.logf("compute: reporting %s %s: %v", id, state, err)
	}
}

func (h *Host) reconcile(ctx context.Context, vm *VM) {
	in := vm.Instance
	switch in.State {
	case ec2meta.StatePending:
		h.mu.Lock()
		last := h.failed[in.ID]
		h.mu.Unlock()
		if time.Since(last) < retryAfter {
			return
		}
		if err := h.start(ctx, vm); err != nil {
			if ctx.Err() != nil {
				return
			}
			h.logf("compute: starting %s: %v", in.ID, err)
			h.mu.Lock()
			if h.failed == nil {
				h.failed = map[string]time.Time{}
			}
			h.failed[in.ID] = time.Now()
			h.mu.Unlock()
			h.report(ctx, in.ID, ec2meta.StatePending, "Server.InternalError: "+firstLine(err.Error()))
			return
		}
		h.mu.Lock()
		delete(h.failed, in.ID)
		h.mu.Unlock()
		h.report(ctx, in.ID, ec2meta.StateRunning, "")
		h.syncVolumes(ctx, vm, true)

	case ec2meta.StateRunning:
		if !h.Driver.Running(vm) {
			// Shut down from inside, crashed, or the PC restarted. EC2
			// stops an instance that shuts itself down.
			h.report(ctx, in.ID, ec2meta.StateStopped, "Client.InstanceInitiatedShutdown: Instance initiated shutdown")
			return
		}
		if seq := readSeq(vm); seq < in.RebootSeq {
			if err := h.Driver.Reboot(vm); err != nil {
				h.logf("compute: rebooting %s: %v", in.ID, err)
				return
			}
			writeSeq(vm, in.RebootSeq)
		}
		h.syncVolumes(ctx, vm, true)

	case ec2meta.StateStopping:
		if err := h.Driver.Stop(ctx, vm, true); err != nil {
			h.logf("compute: stopping %s: %v", in.ID, err)
			return
		}
		h.report(ctx, in.ID, ec2meta.StateStopped, "Client.UserInitiatedShutdown: User initiated shutdown")
		h.syncVolumes(ctx, vm, false)

	case ec2meta.StateStopped:
		if h.Driver.Running(vm) {
			_ = h.Driver.Stop(ctx, vm, false)
		}
		h.syncVolumes(ctx, vm, false)

	case ec2meta.StateShuttingDown:
		if h.destroy(ctx, vm) {
			h.report(ctx, in.ID, ec2meta.StateTerminated, "Client.UserInitiatedShutdown: User initiated shutdown")
		}

	case ec2meta.StateTerminated:
		if _, err := os.Stat(vm.Dir); err == nil {
			h.destroy(ctx, vm)
		}
	}
}

// start prepares and boots an instance.
func (h *Host) start(ctx context.Context, vm *VM) error {
	if vm.Instance.PrivateIP == "" || vm.Subnet == "" {
		return errors.New("no address assigned yet")
	}
	img, err := h.image(ctx, vm.Instance.ImageID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(vm.Dir, 0o700); err != nil {
		return err
	}
	if err := h.Driver.Prepare(ctx, vm, img); err != nil {
		return err
	}
	writeSeq(vm, vm.Instance.RebootSeq)
	return h.boot(ctx, vm)
}

// boot starts a prepared VM with its attached volumes.
func (h *Host) boot(ctx context.Context, vm *VM) error {
	vm.Disks = nil
	for _, v := range vm.Volumes {
		if v.AttachState != ec2meta.AttachAttaching && v.AttachState != ec2meta.AttachAttached {
			continue
		}
		path, err := h.volume(ctx, v)
		if err != nil {
			return err
		}
		vm.Disks = append(vm.Disks, Disk{ID: v.ID, Path: path})
	}
	return h.Driver.Start(ctx, vm)
}

// image returns the path of the cached qcow2 for an image, downloading and
// converting it on first use.
func (h *Host) image(ctx context.Context, id string) (string, error) {
	h.mu.Lock()
	if h.images == nil {
		h.images = map[string]*sync.Mutex{}
	}
	l := h.images[id]
	if l == nil {
		l = &sync.Mutex{}
		h.images[id] = l
	}
	h.mu.Unlock()
	l.Lock()
	defer l.Unlock()

	dir := filepath.Join(h.Dir, "images")
	path := filepath.Join(dir, id+".qcow2")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dl := filepath.Join(dir, id+".download")
	f, err := os.Create(dl)
	if err != nil {
		return "", err
	}
	defer os.Remove(dl)
	h.logf("compute: downloading image %s", id)
	format, err := h.Control.FetchImage(ctx, id, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := h.Driver.ConvertImage(ctx, dl, format, tmp); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return path, os.Rename(tmp, path)
}

// destroy removes a VM and its files. It reports whether it succeeded.
func (h *Host) destroy(ctx context.Context, vm *VM) bool {
	if err := h.Driver.Destroy(ctx, vm); err != nil {
		h.logf("compute: destroying %s: %v", vm.Instance.ID, err)
		return false
	}
	if err := os.RemoveAll(vm.Dir); err != nil {
		h.logf("compute: removing %s: %v", vm.Dir, err)
		return false
	}
	return true
}

// The reboot sequence acted on is kept with the VM, so a jyd restart
// doesn't reboot instances again.
func readSeq(vm *VM) int {
	b, err := os.ReadFile(filepath.Join(vm.Dir, "reboot-seq"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func writeSeq(vm *VM, n int) {
	_ = os.WriteFile(filepath.Join(vm.Dir, "reboot-seq"), []byte(strconv.Itoa(n)+"\n"), 0o600)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
