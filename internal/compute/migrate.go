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
	"github.com/jibzmat/JunkyardServers/internal/vnet"
)

// Live migration. A running instance moves to its replica PC, which
// already holds up-to-date copies of its disks, without stopping:
//
//  1. The source's jyd opens a "migrate" connection to the replica's.
//  2. The replica stops serving the copies itself and boots QEMU waiting
//     for the VM's memory (-incoming), on the copies, with an NBD server
//     exporting them. The source's mirrors reconnect to that NBD server,
//     so writes keep reaching both PCs.
//  3. The source's QEMU sends the VM's memory over the connection, then
//     pauses the guest for the last of it; the replica's QEMU resumes it.
//  4. The replica answers "ok", and the source reports the move and quits
//     its QEMU. Had the replica failed, the source's guest carries on.
//
// The two PCs need compatible CPUs (QEMU runs guests with -cpu host).

// migrateTimeout bounds a migration. A guest dirtying memory faster than
// the network carries it is slowed down (auto-converge), but may still
// not finish.
const migrateTimeout = 30 * time.Minute

// errNotReady is the target's answer when it doesn't expect the instance
// (yet), and notReadyFor how long the source keeps asking.
const (
	errNotReady = "not ready"
	notReadyFor = 2 * time.Minute
)

// migrateRetryAfter is how long a failed migration waits before the next.
const migrateRetryAfter = time.Minute

func (h *Host) migrationSocket(id string) string { return filepath.Join(h.runDir(), "pm-"+id+".sock") }
func (h *Host) incomingSocket(id string) string  { return filepath.Join(h.runDir(), "mi-"+id+".sock") }
func (h *Host) nbdSocket(id string) string       { return filepath.Join(h.runDir(), "n-"+id+".sock") }

// --- source side ---

// migrate moves a running VM to in.MigrateTo once its copies there are in
// step.
func (h *Host) migrate(ctx context.Context, vm *VM) {
	in := vm.Instance
	h.mu.Lock()
	last := h.migrateFailed[in.ID]
	h.mu.Unlock()
	if time.Since(last) < migrateRetryAfter {
		return
	}
	// Every disk must be in step, so nothing is missing on the other side.
	states, err := h.Driver.Mirrors(vm)
	if err != nil {
		return
	}
	plugged, err := h.Driver.Attached(vm)
	if err != nil {
		return
	}
	for _, d := range append([]string{in.ID}, plugged...) {
		if !states[d].Synced {
			return
		}
	}
	ports, err := h.Driver.Ports(vm)
	if err != nil {
		h.logf("compute: migrating %s: %v", in.ID, err)
		return
	}
	start := time.Now()
	reason := h.sendVM(ctx, vm, ports)
	if ctx.Err() != nil {
		return
	}
	if reason == errNotReady {
		// The target hasn't heard of the migration yet; give it a while.
		h.mu.Lock()
		if h.migrateWait == nil {
			h.migrateWait = map[string]time.Time{}
		}
		since, ok := h.migrateWait[in.ID]
		if !ok {
			h.migrateWait[in.ID] = start
		}
		h.mu.Unlock()
		if !ok || start.Sub(since) < notReadyFor {
			return
		}
		reason = "the target PC is not ready"
	}
	h.mu.Lock()
	delete(h.migrateWait, in.ID)
	h.mu.Unlock()
	r := ec2meta.MigrationReport{Instance: in.ID, To: in.MigrateTo, OK: reason == "", Reason: reason}
	if reason != "" {
		h.logf("compute: migrating %s to %s failed: %s", in.ID, in.MigrateTo, reason)
		h.mu.Lock()
		if h.migrateFailed == nil {
			h.migrateFailed = map[string]time.Time{}
		}
		h.migrateFailed[in.ID] = time.Now()
		h.mu.Unlock()
	} else {
		h.logf("compute: migrated %s to %s in %v", in.ID, in.MigrateTo, time.Since(start).Round(time.Millisecond))
		// The guest runs there now; this copy of it stays paused for good,
		// and its disks are out of date from here on.
		if err := h.Driver.Stop(ctx, vm, false); err != nil {
			h.logf("compute: stopping the old copy of %s: %v", in.ID, err)
		} else {
			os.Remove(filepath.Join(vm.Dir, "disk.qcow2"))
			for vol := range ports {
				os.Remove(h.volumePath(vol))
			}
		}
		if h.Net != nil {
			h.Net.Unplug(vnet.TapName(in.ID))
		}
	}
	for {
		err := h.Control.ReportMigration(ctx, r)
		if err == nil || ctx.Err() != nil || reason != "" {
			break
		}
		// The control plane must hear the instance moved, or nobody runs it.
		h.logf("compute: reporting the migration of %s: %v", in.ID, err)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

// sendVM streams the VM's memory to the target and returns why it failed,
// or "" once the target runs the guest. On failure the guest runs here.
func (h *Host) sendVM(ctx context.Context, vm *VM, ports map[string]string) string {
	in := vm.Instance
	ctx, cancel := context.WithTimeout(ctx, migrateTimeout)
	defer cancel()

	dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
	conn, err := h.DialReplica(dctx, in.MigrateTo)
	dcancel()
	if err != nil {
		return "cannot reach the target PC: " + err.Error()
	}
	defer conn.Close()
	b, _ := json.Marshal(replicaHello{Kind: helloMigrate, Disk: in.ID, Ports: ports})
	conn.SetDeadline(time.Now().Add(2 * time.Minute)) // the target boots QEMU first
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return err.Error()
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return "the target PC did not answer: " + err.Error()
	}
	if line = strings.TrimSpace(line); line == errNotReady {
		return errNotReady
	} else if line != "ok" {
		return "the target PC refused: " + line
	}
	conn.SetDeadline(time.Time{})
	h.logf("compute: migrating %s to %s", in.ID, in.MigrateTo)

	sock := h.migrationSocket(in.ID)
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err.Error()
	}
	defer os.Remove(sock)
	defer ln.Close()

	// QEMU writes the stream to sock; it goes on to the target, whose
	// verdict comes back once the stream ends.
	verdict := make(chan string, 1)
	go func() {
		q, err := ln.Accept()
		ln.Close()
		if err != nil {
			verdict <- err.Error()
			return
		}
		defer q.Close()
		if _, err := io.Copy(conn, q); err != nil {
			verdict <- "sending: " + err.Error()
			return
		}
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		line, err := br.ReadString('\n')
		if err != nil {
			verdict <- "the target PC did not confirm: " + err.Error()
			return
		}
		if line = strings.TrimSpace(line); line != "ok" {
			verdict <- "the target PC failed: " + line
			return
		}
		verdict <- ""
	}()

	if err := h.Driver.Migrate(ctx, vm, sock); err != nil {
		conn.Close() // the target gives up and goes back to keeping copies
		ln.Close()
		<-verdict
		return err.Error()
	}
	// The guest is paused here with all its memory sent.
	select {
	case v := <-verdict:
		if v == "" {
			return ""
		}
		if err := h.Driver.Resume(vm); err != nil {
			h.logf("compute: resuming %s: %v", in.ID, err)
		}
		return v
	case <-ctx.Done():
		conn.Close()
		if err := h.Driver.Resume(vm); err != nil {
			h.logf("compute: resuming %s: %v", in.ID, err)
		}
		return "timed out"
	}
}

// --- target side ---

// receiveVM handles a migrate connection from an instance's host: it
// boots the instance on this PC's copies and loads the VM's memory from c.
func (h *Host) receiveVM(c net.Conn, br *bufio.Reader, node string, hello replicaHello) {
	refuse := func(format string, args ...any) {
		fmt.Fprintf(c, format+"\n", args...)
	}
	h.mu.Lock()
	vm := h.incoming[hello.Disk]
	h.mu.Unlock()
	if vm == nil || vm.Instance.Host != node {
		refuse(errNotReady) // it may not have reached this PC's view yet
		return
	}
	vm = &VM{Instance: vm.Instance, Subnet: vm.Subnet, NetNS: vm.NetNS, Dir: vm.Dir}
	id := vm.Instance.ID
	disks := []string{id}
	for vol, bus := range hello.Ports {
		h.mu.Lock()
		primary := h.replicaFor[vol]
		h.mu.Unlock()
		if !validDisk(vol) || !strings.HasPrefix(vol, "vol-") || primary != node || !validBus(bus) {
			refuse("this PC keeps no copy of %s for %s", vol, node)
			return
		}
		disks = append(disks, vol)
		vm.Disks = append(vm.Disks, Disk{ID: vol, Path: h.volumePath(vol), Bus: bus})
	}
	for _, d := range disks {
		if _, err := os.Stat(h.replicaPath(d)); err != nil {
			refuse("this PC has no copy of %s", d)
			return
		}
	}
	h.mu.Lock()
	if h.busy[id] || h.migrating[id] != "" {
		h.mu.Unlock()
		refuse("already busy with %s", id)
		return
	}
	if h.busy == nil {
		h.busy = map[string]bool{}
	}
	h.busy[id] = true // no other work on it until this is done
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.busy, id)
		h.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), migrateTimeout)
	defer cancel()
	ok := false
	paths := map[string]string{id: filepath.Join(vm.Dir, "disk.qcow2")}
	for _, d := range vm.Disks {
		paths[d.ID] = d.Path
	}
	nbd := h.nbdSocket(id)
	defer func() {
		h.mu.Lock()
		for _, d := range disks {
			delete(h.migrating, d)
		}
		h.mu.Unlock()
		if ok {
			return
		}
		// Back to keeping copies: they start over when the mirrors do.
		if err := h.Driver.Destroy(context.Background(), vm); err != nil {
			h.logf("compute: stopping the incoming %s: %v", id, err)
		}
		for d, p := range paths {
			os.Rename(p, h.replicaPath(d))
		}
		os.RemoveAll(vm.Dir)
	}()

	// The copies stop being served by qemu-nbd and move into place; the
	// mirrors reconnect to the incoming QEMU's NBD server.
	h.mu.Lock()
	if h.migrating == nil {
		h.migrating = map[string]string{}
	}
	for _, d := range disks {
		h.migrating[d] = nbd
	}
	h.mu.Unlock()
	for _, d := range disks {
		h.dropConn(d)
		h.Driver.Unexport(h.exportSocket(d))
	}
	if err := os.MkdirAll(vm.Dir, 0o700); err != nil {
		refuse("%v", err)
		return
	}
	if err := os.MkdirAll(filepath.Join(h.Dir, "volumes"), 0o700); err != nil {
		refuse("%v", err)
		return
	}
	for d, p := range paths {
		if err := os.Rename(h.replicaPath(d), p); err != nil {
			refuse("%v", err)
			return
		}
	}
	if err := h.Driver.Prepare(ctx, vm, ""); err != nil { // the cloud-init seed
		h.logf("compute: receiving %s: %v", id, err)
		refuse("cannot prepare the instance")
		return
	}
	writeSeq(vm, vm.Instance.RebootSeq)
	sock := h.incomingSocket(id)
	if err := h.Driver.StartIncoming(ctx, vm, sock, nbd, disks); err != nil {
		h.logf("compute: receiving %s: %v", id, err)
		refuse("cannot start the instance")
		return
	}
	q, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		refuse("cannot start the instance")
		return
	}
	defer q.Close()
	if _, err := io.WriteString(c, "ok\n"); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	h.logf("compute: receiving %s from %s", id, node)
	if _, err := io.Copy(q, br); err != nil {
		h.logf("compute: receiving %s: %v", id, err)
		return
	}
	if cw, ok := q.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	if err := h.Driver.FinishIncoming(ctx, vm); err != nil {
		h.logf("compute: receiving %s: %v", id, err)
		refuse("%s", firstLine(err.Error()))
		return
	}
	// The disks are this PC's own now. The old host's paused copy still
	// has mirrors that reconnect until it stops; they must not get a
	// fresh copy made here (it would be blank, and taken for the disk).
	h.mu.Lock()
	if h.arrived == nil {
		h.arrived = map[string]string{}
	}
	for _, d := range disks {
		h.arrived[d] = node
		delete(h.replicaFor, d)
	}
	h.mu.Unlock()
	if h.Net != nil {
		if err := h.Net.Plug(ctx, vm.Instance.VpcID, vnet.TapName(id), vm.Instance.PrivateIP); err != nil {
			h.logf("compute: routing %s: %v", id, err)
		}
	}
	ok = true
	h.logf("compute: %s runs here now", id)
	io.WriteString(c, "ok\n")
}

// validBus accepts the root port names QEMU gives volumes (rp1...).
func validBus(bus string) bool {
	for i := 1; i <= rootPorts; i++ {
		if bus == fmt.Sprintf("rp%d", i) {
			return true
		}
	}
	return false
}

// --- QEMU ---

// Ports returns the root port each plugged volume is on, so the target
// recreates the same devices.
func (q *QEMU) Ports(vm *VM) (map[string]string, error) {
	ids, err := q.Attached(vm)
	if err != nil {
		return nil, err
	}
	ports := map[string]string{}
	for _, id := range ids {
		out, err := qmpRun(vm, qmpCmd{"qom-get", map[string]any{"path": "/machine/peripheral/" + deviceID(id), "property": "parent_bus"}})
		if err != nil {
			return nil, err
		}
		var bus string
		if err := json.Unmarshal(out[0], &bus); err != nil {
			return nil, err
		}
		// /machine/peripheral/rp2/rp2: the port's own bus.
		rest, ok := strings.CutPrefix(bus, "/machine/peripheral/")
		port, _, _ := strings.Cut(rest, "/")
		if !ok || port == "" {
			return nil, fmt.Errorf("compute: %s is on an unexpected bus %q", id, bus)
		}
		ports[id] = port
	}
	return ports, nil
}

// StartIncoming boots QEMU waiting for a migration on socket, and serves
// the disks it opened over NBD on nbd, so mirrors keep writing to them.
func (q *QEMU) StartIncoming(ctx context.Context, vm *VM, socket, nbd string, disks []string) error {
	os.Remove(socket)
	os.Remove(nbd)
	if err := q.launch(ctx, vm, "-incoming", "unix:"+socket); err != nil {
		return err
	}
	cmds := []qmpCmd{{"nbd-server-start", map[string]any{"addr": map[string]any{"type": "unix", "data": map[string]any{"path": nbd}}}}}
	for _, d := range disks {
		cmds = append(cmds, qmpCmd{"nbd-server-add", map[string]any{"device": diskNode(vm, d), "name": d, "writable": true}})
	}
	if _, err := qmpRun(vm, cmds...); err != nil {
		_ = q.Destroy(ctx, vm)
		return err
	}
	return nil
}

// FinishIncoming waits for the guest to run after its memory arrived, and
// stops the NBD server.
func (q *QEMU) FinishIncoming(ctx context.Context, vm *VM) error {
	deadline := time.Now().Add(time.Minute)
	for {
		out, err := qmpRun(vm, qmpCmd{Execute: "query-status"})
		if err != nil {
			return err
		}
		var st struct {
			Status string `json:"status"`
		}
		json.Unmarshal(out[0], &st)
		if st.Status == "running" {
			break
		}
		if st.Status != "inmigrate" || time.Now().After(deadline) {
			return fmt.Errorf("the guest did not resume (%s)", st.Status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if _, err := qmpRun(vm, qmpCmd{Execute: "nbd-server-stop"}); err != nil {
		return err
	}
	return nil
}

// Migrate sends the VM to the incoming QEMU at socket and waits until all
// of it is sent; the guest is then paused here.
func (q *QEMU) Migrate(ctx context.Context, vm *VM, socket string) error {
	_, err := qmpRun(vm,
		// Slow down a guest that dirties memory faster than it is sent.
		qmpCmd{"migrate-set-capabilities", map[string]any{"capabilities": []map[string]any{{"capability": "auto-converge", "state": true}}}},
		qmpCmd{"migrate-set-parameters", map[string]any{"max-bandwidth": int64(1) << 30}},
		qmpCmd{"migrate", map[string]any{"uri": "unix:" + socket}})
	if err != nil {
		return err
	}
	for {
		out, err := qmpRun(vm, qmpCmd{Execute: "query-migrate"})
		if err != nil {
			return err
		}
		var st struct {
			Status    string `json:"status"`
			ErrorDesc string `json:"error-desc"`
		}
		json.Unmarshal(out[0], &st)
		switch st.Status {
		case "completed":
			return nil
		case "failed", "cancelled":
			if st.ErrorDesc != "" {
				return errors.New(st.ErrorDesc)
			}
			return fmt.Errorf("migration %s", st.Status)
		}
		select {
		case <-ctx.Done():
			_, _ = qmpRun(vm, qmpCmd{Execute: "migrate_cancel"})
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Resume runs a guest paused by a migration that the target failed.
func (q *QEMU) Resume(vm *VM) error { return qmp(vm, "cont") }
