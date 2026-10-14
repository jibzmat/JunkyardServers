// Package compute runs EC2 instances on a compute host. The host polls the
// control plane for the instances assigned to it, makes the local VMs
// match (boot, stop, reboot, destroy) and reports their actual state.
package compute

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/vnet"
)

// VM is an instance as this host runs it.
type VM struct {
	Instance ec2meta.Instance
	Subnet   string // the instance's subnet, e.g. 172.31.0.0/20
	NetNS    string // the network namespace of its VPC
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

	// Mirrors reports a running VM's disk mirrors, by disk (the instance
	// ID for the root disk, else the volume ID).
	Mirrors(vm *VM) (map[string]MirrorState, error)
	// StartMirror starts copying a disk, and then every write to it, to
	// the NBD server on socket.
	StartMirror(ctx context.Context, vm *VM, disk, socket string) error
	// StopMirror stops a disk's mirror.
	StopMirror(ctx context.Context, vm *VM, disk string) error
	// DiskSize is a disk file's virtual size in bytes.
	DiskSize(ctx context.Context, path string) (int64, error)
	// Export serves a disk copy (made blank at size if missing) over NBD
	// on socket, unless it already is.
	Export(ctx context.Context, path string, size int64, socket string) error
	// Unexport stops serving the copy on socket.
	Unexport(socket string)
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
	ReportReplica(ctx context.Context, r ec2meta.ReplicaReport) error
}

// Network is the PC's VPC networking; *vnet.Manager implements it.
type Network interface {
	Sync(ctx context.Context, node, meshIP string, nets []ec2meta.VPCNet) error
	Plug(ctx context.Context, vpcID, tap, ip string) error
	Unplug(tap string)
	Listen(vpcID, addr string) (net.Listener, error)
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
	// Net runs VPC networking; nil runs instances without (tests).
	Net Network
	// DialReplica connects to another compute PC's replica server
	// (ServeReplicas); nil keeps no disk copies.
	DialReplica func(ctx context.Context, node string) (net.Conn, error)
	// RunDir holds unix sockets; default /run/junkyard.
	RunDir string

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
	inflight sync.WaitGroup

	// Disk replicas (replica.go).
	proxies       map[string]*mirrorProxy // disk -> this host's mirror proxy
	mirrorTo      map[string]string       // instance -> replica its mirrors go to
	behind        map[string]time.Time    // disk -> since when its mirror is out of step
	replicaFor    map[string]string       // disk -> primary, for copies kept here
	staleReplicas map[string]time.Time    // copies no longer wanted, since when
	replicaConns  map[string]net.Conn     // disk -> its primary's connection
	retries       map[string]*mirrorRetry // instance -> when to start its mirrors again
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
	var netErr error
	if h.Net != nil {
		// A VPC that fails to set up fails its instances' starts; the
		// others carry on.
		netErr = h.Net.Sync(ctx, v.Node, v.MeshIP, v.Networks)
		if netErr != nil && ctx.Err() == nil {
			h.logf("compute: networking: %v", netErr)
		}
		if h.Metadata {
			h.syncMetadata(ctx, v.Networks)
		}
	}
	subnets := map[string]string{}
	for _, n := range v.Networks {
		for _, sn := range n.Subnets {
			subnets[sn.ID] = sn.CIDR
		}
	}
	byIP := map[string]ec2meta.Instance{}
	for _, in := range v.Instances {
		if in.PrivateIP != "" && in.State != ec2meta.StateTerminated {
			byIP[in.VpcID+"/"+in.PrivateIP] = in
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
	h.syncReplicas(ctx, v)
	mirrored := map[string]bool{}
	for _, in := range v.Instances {
		if in.Replica != "" && (in.State == ec2meta.StateRunning || in.State == ec2meta.StatePending) {
			mirrored[in.ID] = true
			for _, vol := range attached[in.ID] {
				mirrored[vol.ID] = true
			}
		}
	}
	h.closeProxies(mirrored)
	assigned := map[string]bool{}
	for _, in := range v.Instances {
		assigned[in.ID] = true
		vm := &VM{Instance: in, Subnet: subnets[in.SubnetID], NetNS: vnet.NSName(in.VpcID), Dir: h.instanceDir(in.ID), Volumes: attached[in.ID]}
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
		h.syncMirrors(ctx, vm)

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
		return errors.New("the instance's subnet is unknown")
	}
	img, err := h.image(ctx, vm.Instance.ImageID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(vm.Dir, 0o700); err != nil {
		return err
	}
	// After a failover the root disk is this PC's copy, never a new one.
	disk := filepath.Join(vm.Dir, "disk.qcow2")
	adopted, err := h.adopt(vm.Instance.ID, disk)
	if err != nil {
		return err
	}
	if _, err := os.Stat(disk); err != nil && !adopted && vm.Instance.Recovered {
		return errors.New("the copy of the root disk is missing from this PC")
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
	if err := h.Driver.Start(ctx, vm); err != nil {
		return err
	}
	if h.Net != nil {
		return h.Net.Plug(ctx, vm.Instance.VpcID, vnet.TapName(vm.Instance.ID), vm.Instance.PrivateIP)
	}
	return nil
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
	if h.Net != nil {
		h.Net.Unplug(vnet.TapName(vm.Instance.ID))
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
