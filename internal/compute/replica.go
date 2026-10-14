package compute

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// Disk replicas. A running instance's host mirrors every write to its root
// disk and attached volumes to the instance's replica PC before the guest
// sees the write complete (QEMU's mirror job in write-blocking mode). The
// replica stores the copies as qcow2 files served over NBD to a local
// socket; the hosts' jyds carry the NBD stream between PCs over mutual TLS.
// If the host is lost, the control plane moves the instance to the replica,
// which boots it from the copies.

// MirrorState is how far one disk's mirror job is.
type MirrorState struct {
	Ready  bool // the first full copy is done
	Synced bool // and every write since has reached the copy
}

// mirrorBehindLimit is how long a mirror may stay ready but out of step
// (the replica stopped answering) before it is restarted from scratch.
const mirrorBehindLimit = 30 * time.Second

// replicaHello opens a replica connection: which disk, and its size so
// the replica can create its copy.
type replicaHello struct {
	Disk string `json:"disk"`
	Size int64  `json:"size,omitempty"`
	// Kind is empty for a mirror, or helloMigrate to send the instance
	// Disk itself (migrate.go), its volumes on Ports.
	Kind  string            `json:"kind,omitempty"`
	Ports map[string]string `json:"ports,omitempty"`
}

const helloMigrate = "migrate"

func (h *Host) runDir() string {
	if h.RunDir != "" {
		return h.RunDir
	}
	return "/run/junkyard"
}

func (h *Host) replicaPath(disk string) string {
	p := filepath.Join(h.Dir, "replicas", disk+".qcow2")
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// Unix socket paths are limited to 108 bytes, so sockets live in a short
// runtime directory. p- sockets carry a primary's mirror to its proxy, r-
// sockets are a replica's NBD servers.
func (h *Host) proxySocket(disk string) string  { return filepath.Join(h.runDir(), "p-"+disk+".sock") }
func (h *Host) exportSocket(disk string) string { return filepath.Join(h.runDir(), "r-"+disk+".sock") }

// --- primary side ---

// mirrorProxy accepts QEMU's NBD connections for one disk and carries each
// to the replica PC.
type mirrorProxy struct {
	node string
	size int64
	ln   net.Listener
}

// proxy returns the socket QEMU mirrors disk to, listening on it if needed.
func (h *Host) proxy(disk, node string, size int64) (string, error) {
	sock := h.proxySocket(disk)
	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.proxies[disk]; ok {
		if p.node == node {
			p.size = size
			return sock, nil
		}
		p.ln.Close()
		delete(h.proxies, disk)
	}
	if err := os.MkdirAll(h.runDir(), 0o700); err != nil {
		return "", err
	}
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return "", err
	}
	p := &mirrorProxy{node: node, size: size, ln: ln}
	if h.proxies == nil {
		h.proxies = map[string]*mirrorProxy{}
	}
	h.proxies[disk] = p
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.carry(c, disk, p)
		}
	}()
	return sock, nil
}

func (h *Host) carry(c net.Conn, disk string, p *mirrorProxy) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	r, err := h.DialReplica(ctx, p.node)
	cancel()
	if err != nil {
		h.logf("compute: replica of %s on %s: %v", disk, p.node, err)
		return
	}
	defer r.Close()
	h.mu.Lock()
	size := p.size
	h.mu.Unlock()
	b, _ := json.Marshal(replicaHello{Disk: disk, Size: size})
	r.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := r.Write(append(b, '\n')); err != nil {
		return
	}
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	if line = strings.TrimSpace(line); line != "ok" {
		h.logf("compute: replica of %s on %s refused: %s", disk, p.node, line)
		return
	}
	r.SetDeadline(time.Time{})
	splice(c, bufConn{r, br})
}

// bufConn reads through the buffer that read the connection's first line.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// splice copies both ways until either side closes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

// closeProxies stops proxies for disks not in keep.
func (h *Host) closeProxies(keep map[string]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for disk, p := range h.proxies {
		if !keep[disk] {
			p.ln.Close()
			os.Remove(h.proxySocket(disk))
			delete(h.proxies, disk)
		}
	}
}

// syncMirrors keeps a running VM's disks mirrored to its replica and
// reports how far the copies are.
func (h *Host) syncMirrors(ctx context.Context, vm *VM) {
	if h.DialReplica == nil {
		return
	}
	in := vm.Instance
	states, err := h.Driver.Mirrors(vm)
	if err != nil {
		h.logf("compute: mirrors of %s: %v", in.ID, err)
		return
	}
	h.mu.Lock()
	if h.mirrorTo == nil {
		h.mirrorTo = map[string]string{}
	}
	prev, known := h.mirrorTo[in.ID]
	h.mirrorTo[in.ID] = in.Replica
	h.mu.Unlock()
	if known && prev != in.Replica || in.Replica == "" {
		for disk := range states {
			if err := h.Driver.StopMirror(ctx, vm, disk); err != nil {
				h.logf("compute: stopping mirror of %s: %v", disk, err)
			}
		}
		states = nil
	}
	if in.Replica == "" {
		return
	}

	disks := []Disk{{ID: in.ID, Path: filepath.Join(vm.Dir, "disk.qcow2")}}
	plugged, err := h.Driver.Attached(vm)
	if err != nil {
		h.logf("compute: mirrors of %s: %v", in.ID, err)
		return
	}
	isPlugged := map[string]bool{}
	for _, id := range plugged {
		isPlugged[id] = true
	}
	wasSynced := map[string]bool{in.ID: in.ReplicaSynced}
	for _, v := range vm.Volumes {
		if isPlugged[v.ID] {
			disks = append(disks, Disk{ID: v.ID, Path: h.volumePath(v.ID)})
			wasSynced[v.ID] = v.ReplicaSynced && v.Replica == in.Replica
		}
	}

	synced := true
	var syncedVols []string
	var start []Disk
	now := time.Now()
	for _, d := range disks {
		st, ok := states[d.ID]
		if ok && st.Ready && !st.Synced {
			h.mu.Lock()
			if h.behind == nil {
				h.behind = map[string]time.Time{}
			}
			since, seen := h.behind[d.ID]
			if !seen {
				h.behind[d.ID] = now
			}
			h.mu.Unlock()
			if seen && now.Sub(since) > mirrorBehindLimit {
				h.logf("compute: mirror of %s fell behind; copying it again", d.ID)
				if err := h.Driver.StopMirror(ctx, vm, d.ID); err == nil {
					ok = false
				}
			}
		} else {
			h.mu.Lock()
			delete(h.behind, d.ID)
			h.mu.Unlock()
		}
		switch {
		case ok && st.Ready && st.Synced:
			if d.ID != in.ID {
				syncedVols = append(syncedVols, d.ID)
			}
		case ok:
			synced = false
		default:
			synced = false
			start = append(start, d)
		}
	}

	// A copy is overwritten from scratch when its mirror starts, so the
	// control plane must stop counting on it first.
	mustReport := false
	for _, d := range start {
		if wasSynced[d.ID] {
			mustReport = true
		}
	}
	if mustReport {
		r := ec2meta.ReplicaReport{Instance: in.ID, Replica: in.Replica, Synced: false, Volumes: syncedVols}
		if err := h.Control.ReportReplica(ctx, r); err != nil {
			h.logf("compute: reporting replica of %s: %v", in.ID, err)
			return
		}
		for _, d := range start {
			wasSynced[d.ID] = false
		}
		wasSynced[in.ID] = false
	}

	// Starting a mirror blocks the VM while QEMU connects to the copy, so
	// only start when the replica answers, and not again for a while after
	// a try that failed.
	if len(start) > 0 && !h.mayStartMirrors(ctx, in.ID, in.Replica) {
		start = nil
	}

	keep := map[string]bool{}
	for _, d := range disks {
		keep[d.ID] = true
		size, err := h.Driver.DiskSize(ctx, d.Path)
		if err != nil {
			h.logf("compute: mirror of %s: %v", d.ID, err)
			synced = false
			continue
		}
		sock, err := h.proxy(d.ID, in.Replica, size)
		if err != nil {
			h.logf("compute: mirror of %s: %v", d.ID, err)
			synced = false
			continue
		}
		for _, s := range start {
			if s.ID == d.ID {
				if err := h.Driver.StartMirror(ctx, vm, d.ID, sock); err != nil {
					h.logf("compute: mirroring %s to %s: %v", d.ID, in.Replica, err)
					h.mirrorFailed(in.ID)
				}
			}
		}
	}

	if synced {
		h.mirrorSynced(in.ID)
	}
	changed := synced != wasSynced[in.ID]
	for _, d := range disks[1:] {
		now := false
		for _, id := range syncedVols {
			if id == d.ID {
				now = true
			}
		}
		if now != wasSynced[d.ID] {
			changed = true
		}
	}
	if changed {
		r := ec2meta.ReplicaReport{Instance: in.ID, Replica: in.Replica, Synced: synced, Volumes: syncedVols}
		if err := h.Control.ReportReplica(ctx, r); err != nil && ctx.Err() == nil {
			h.logf("compute: reporting replica of %s: %v", in.ID, err)
		}
	}
}

// mirrorBackoff bounds how often a VM's mirrors are restarted.
const (
	mirrorBackoffMin = 30 * time.Second
	mirrorBackoffMax = 10 * time.Minute
)

type mirrorRetry struct {
	next time.Time
	wait time.Duration
}

// mayStartMirrors reports whether to start an instance's mirrors now: not
// while backing off, and only if the replica PC answers. Every start
// counts as a try, so a mirror that keeps failing is retried less often.
func (h *Host) mayStartMirrors(ctx context.Context, instance, node string) bool {
	h.mu.Lock()
	r := h.retries[instance]
	h.mu.Unlock()
	if r != nil && time.Now().Before(r.next) {
		return false
	}
	h.mirrorFailed(instance) // until the copy is in step (see mirrorSynced)
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := h.DialReplica(dctx, node)
	if err != nil {
		h.logf("compute: not mirroring %s: replica %s: %v", instance, node, err)
		return false
	}
	c.Close()
	return true
}

func (h *Host) mirrorFailed(instance string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.retries == nil {
		h.retries = map[string]*mirrorRetry{}
	}
	r := h.retries[instance]
	if r == nil {
		r = &mirrorRetry{}
		h.retries[instance] = r
	}
	if time.Now().Before(r.next) {
		return
	}
	switch {
	case r.wait == 0:
		r.wait = mirrorBackoffMin
	case r.wait < mirrorBackoffMax:
		r.wait *= 2
	}
	r.next = time.Now().Add(r.wait)
}

// mirrorSynced resets the backoff once an instance's copies are in step.
func (h *Host) mirrorSynced(instance string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.retries, instance)
}

// --- replica side ---

// syncReplicas records which disks this host keeps copies of (and for
// whom), and removes copies no longer wanted.
func (h *Host) syncReplicas(ctx context.Context, v *ec2meta.HostView) {
	allowed := map[string]string{}
	for _, r := range v.Replicas {
		allowed[r.ID] = r.Primary
	}
	owned := map[string]bool{}
	for _, in := range v.Instances {
		owned[in.ID] = true
	}
	for _, vol := range v.Volumes {
		owned[vol.ID] = true
	}
	h.mu.Lock()
	h.replicaFor = allowed
	h.mu.Unlock()

	entries, _ := os.ReadDir(filepath.Join(h.Dir, "replicas"))
	var gone []string
	h.mu.Lock()
	if h.staleReplicas == nil {
		h.staleReplicas = map[string]time.Time{}
	}
	seen := map[string]bool{}
	for _, e := range entries {
		disk, ok := strings.CutSuffix(e.Name(), ".qcow2")
		if !ok {
			continue
		}
		if _, ok := allowed[disk]; ok || owned[disk] {
			continue // wanted, or about to become this host's own disk
		}
		seen[disk] = true
		if since, ok := h.staleReplicas[disk]; !ok {
			h.staleReplicas[disk] = time.Now()
		} else if time.Since(since) >= destroyAfter {
			gone = append(gone, disk)
		}
	}
	for disk := range h.staleReplicas {
		if !seen[disk] {
			delete(h.staleReplicas, disk)
		}
	}
	h.mu.Unlock()
	for _, disk := range gone {
		h.dropConn(disk)
		h.Driver.Unexport(h.exportSocket(disk))
		if err := os.Remove(h.replicaPath(disk)); err != nil && !errors.Is(err, os.ErrNotExist) {
			h.logf("compute: removing copy of %s: %v", disk, err)
			continue
		}
		h.logf("compute: removed the copy of %s", disk)
	}
}

// ServeReplicas accepts primaries' mirror connections until ln closes.
// peer names the node at the other end of a connection (from its TLS
// certificate).
func (h *Host) ServeReplicas(ln net.Listener, peer func(net.Conn) (string, error)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go h.serveReplica(c, peer)
	}
}

func (h *Host) serveReplica(c net.Conn, peer func(net.Conn) (string, error)) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	node, err := peer(c)
	if err != nil {
		return
	}
	br := bufio.NewReader(c)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return
	}
	var hello replicaHello
	refuse := func(format string, args ...any) {
		fmt.Fprintf(c, format+"\n", args...)
	}
	if err := json.Unmarshal(line, &hello); err != nil || !validDisk(hello.Disk) {
		refuse("bad request")
		return
	}
	if hello.Kind == helloMigrate && strings.HasPrefix(hello.Disk, "i-") {
		h.receiveVM(c, br, node, hello)
		return
	}
	if hello.Kind != "" || hello.Size <= 0 {
		refuse("bad request")
		return
	}
	h.mu.Lock()
	primary := h.replicaFor[hello.Disk]
	h.mu.Unlock()
	if primary == "" || primary != node {
		refuse("this PC keeps no copy of %s for %s", hello.Disk, node)
		return
	}
	// One writer per copy: a new connection replaces a stale one.
	h.dropConn(hello.Disk)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h.mu.Lock()
	nbdSock := h.migrating[hello.Disk]
	h.mu.Unlock()
	if nbdSock != "" {
		// The instance is migrating here: its mirror now writes to the
		// incoming QEMU, which has the copy open.
		nbd, err := net.DialTimeout("unix", nbdSock, 5*time.Second)
		if err != nil {
			refuse("cannot serve the copy")
			return
		}
		h.spliceReplica(c, br, hello.Disk, nbd)
		return
	}
	sock := h.exportSocket(hello.Disk)
	if err := os.MkdirAll(filepath.Dir(h.replicaPath(hello.Disk)), 0o700); err != nil {
		refuse("%v", err)
		return
	}
	if err := os.MkdirAll(h.runDir(), 0o700); err != nil {
		refuse("%v", err)
		return
	}
	if err := h.Driver.Export(ctx, h.replicaPath(hello.Disk), hello.Disk, hello.Size, sock); err != nil {
		h.logf("compute: serving the copy of %s: %v", hello.Disk, err)
		refuse("cannot serve the copy")
		return
	}
	nbd, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		refuse("cannot serve the copy")
		return
	}
	h.spliceReplica(c, br, hello.Disk, nbd)
}

// spliceReplica accepts a mirror connection and carries it to the NBD
// server nbd.
func (h *Host) spliceReplica(c net.Conn, br *bufio.Reader, disk string, nbd net.Conn) {
	if _, err := io.WriteString(c, "ok\n"); err != nil {
		nbd.Close()
		return
	}
	c.SetDeadline(time.Time{})
	h.mu.Lock()
	if h.replicaConns == nil {
		h.replicaConns = map[string]net.Conn{}
	}
	h.replicaConns[disk] = c
	h.mu.Unlock()
	splice(bufConn{c, br}, nbd)
	h.mu.Lock()
	if h.replicaConns[disk] == c {
		delete(h.replicaConns, disk)
	}
	h.mu.Unlock()
}

func (h *Host) dropConn(disk string) {
	h.mu.Lock()
	c := h.replicaConns[disk]
	delete(h.replicaConns, disk)
	h.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// validDisk accepts instance and volume IDs only (they become file names).
func validDisk(id string) bool {
	if !strings.HasPrefix(id, "i-") && !strings.HasPrefix(id, "vol-") {
		return false
	}
	for _, r := range id {
		if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return len(id) <= 32
}

// adopt makes this host's copy of a disk its own after a failover: the
// copy stops being served and moves to dst. It reports whether there was
// a copy.
func (h *Host) adopt(disk, dst string) (bool, error) {
	src := h.replicaPath(disk)
	if _, err := os.Stat(src); err != nil {
		return false, nil
	}
	h.dropConn(disk)
	h.Driver.Unexport(h.exportSocket(disk))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return false, err
	}
	if err := os.Rename(src, dst); err != nil {
		return false, err
	}
	h.logf("compute: taking over %s from its copy", disk)
	return true, nil
}
