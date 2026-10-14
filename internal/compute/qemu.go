package compute

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
)

// QEMU runs instances as QEMU processes with KVM, or under QEMU's emulator
// when the PC has no KVM (slow; for trying things out). Each VM is a
// daemonised process that outlives jyd restarts, with a tap on the host's
// bridge, a qcow2 disk backed by the cached image and a cloud-init seed.
type QEMU struct {
	// Bridge is the host bridge instances attach to.
	Bridge string
	// Emulate runs guests under TCG instead of KVM.
	Emulate bool
	// Binary is the QEMU system emulator; default qemu-system-x86_64.
	Binary string
}

const defaultBridge = "jybr0"

func (q *QEMU) bridge() string {
	if q.Bridge == "" {
		return defaultBridge
	}
	return q.Bridge
}

func (q *QEMU) binary() string {
	if q.Binary == "" {
		return "qemu-system-x86_64"
	}
	return q.Binary
}

// Check reports what's missing to run instances.
func (q *QEMU) Check() error {
	var missing []string
	for _, b := range []string{q.binary(), "qemu-img", "ip", "iptables", "ebtables"} {
		if _, err := exec.LookPath(b); err != nil {
			missing = append(missing, b)
		}
	}
	if isoTool() == nil {
		missing = append(missing, "genisoimage, mkisofs or xorriso")
	}
	if len(missing) > 0 {
		return fmt.Errorf("compute: missing %s", strings.Join(missing, ", "))
	}
	if !q.Emulate {
		if _, err := os.Stat("/dev/kvm"); err != nil {
			return errors.New("compute: /dev/kvm is not available (pass -emulate to run guests slowly without it)")
		}
	}
	return nil
}

func run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// Network sets up the bridge for subnet, with the host as .1, forwarding,
// and NAT for traffic leaving the cluster. Traffic to the mesh and to
// other hosts' instances is routed, not NATed. It is idempotent.
func (q *QEMU) Network(ctx context.Context, subnet netip.Prefix) error {
	br := q.bridge()
	gw := netip.PrefixFrom(subnet.Addr().Next(), subnet.Bits())
	if _, err := net.InterfaceByName(br); err != nil {
		if err := run(ctx, "ip", "link", "add", br, "type", "bridge"); err != nil {
			return err
		}
	}
	if err := run(ctx, "ip", "addr", "replace", gw.String(), "dev", br); err != nil {
		return err
	}
	if err := run(ctx, "ip", "link", "set", br, "up"); err != nil {
		return err
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("compute: enabling forwarding: %w", err)
	}
	// Our own chains, rebuilt each time, hooked in once.
	rules := []struct {
		table, chain, hook string
		rules              [][]string
	}{
		{"nat", "JY-NAT", "POSTROUTING", [][]string{
			{"-d", subnet.String(), "-j", "RETURN"},
			{"-d", "100.64.0.0/10", "-j", "RETURN"},
			{"-d", cluster.VMCIDR, "-j", "RETURN"},
			{"-s", subnet.String(), "-j", "MASQUERADE"},
		}},
		{"filter", "JY-FORWARD", "FORWARD", [][]string{
			{"-i", br, "-j", "ACCEPT"},
			{"-o", br, "-j", "ACCEPT"},
		}},
		// The metadata service, as guests address it.
		{"nat", "JY-PRE", "PREROUTING", [][]string{
			{"-i", br, "-d", MetadataIP + "/32", "-p", "tcp", "--dport", "80",
				"-j", "DNAT", "--to-destination", net.JoinHostPort(gw.Addr().String(), strconv.Itoa(MetadataPort))},
		}},
		{"filter", "JY-INPUT", "INPUT", [][]string{
			{"-i", br, "-p", "tcp", "--dport", strconv.Itoa(MetadataPort), "-j", "ACCEPT"},
		}},
	}
	for _, r := range rules {
		_ = run(ctx, "iptables", "-t", r.table, "-N", r.chain) // exists already is fine
		if err := run(ctx, "iptables", "-t", r.table, "-F", r.chain); err != nil {
			return err
		}
		for _, rule := range r.rules {
			if err := run(ctx, "iptables", append([]string{"-t", r.table, "-A", r.chain}, rule...)...); err != nil {
				return err
			}
		}
		if run(ctx, "iptables", "-t", r.table, "-C", r.hook, "-j", r.chain) != nil {
			if err := run(ctx, "iptables", "-t", r.table, "-I", r.hook, "-j", r.chain); err != nil {
				return err
			}
		}
	}
	return nil
}

// ConvertImage turns a downloaded image into the qcow2 instances' disks
// are backed by.
func (q *QEMU) ConvertImage(ctx context.Context, src, format, dst string) error {
	if format != "raw" && format != "qcow2" {
		return fmt.Errorf("compute: unsupported image format %q", format)
	}
	return run(ctx, "qemu-img", "convert", "-f", format, "-O", "qcow2", src, dst)
}

// tap is the tap device name for an instance (at most 15 characters).
func tap(id string) string {
	id = strings.TrimPrefix(id, "i-")
	if len(id) > 13 {
		id = id[:13]
	}
	return "jy" + id
}

// Prepare creates an instance's disk (a qcow2 overlay on image, grown to
// the root size) and its cloud-init seed, unless they exist.
func (q *QEMU) Prepare(ctx context.Context, vm *VM, image string) error {
	disk := filepath.Join(vm.Dir, "disk.qcow2")
	// qemu-img resolves a relative backing file against the overlay's
	// directory, so pass an absolute one.
	image, err := filepath.Abs(image)
	if err != nil {
		return err
	}
	if _, err := os.Stat(disk); errors.Is(err, os.ErrNotExist) {
		size := strconv.Itoa(vm.Instance.RootGiB) + "G"
		tmp := disk + ".tmp"
		if err := run(ctx, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image, tmp); err != nil {
			return err
		}
		// Grow to the requested size; images larger than it keep their size.
		_ = run(ctx, "qemu-img", "resize", "-q", tmp, size)
		if err := os.Rename(tmp, disk); err != nil {
			return err
		}
	}
	seed := filepath.Join(vm.Dir, "seed.iso")
	if _, err := os.Stat(seed); err == nil {
		return nil
	}
	dir := filepath.Join(vm.Dir, "seed")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sub, err := netip.ParsePrefix(vm.Subnet)
	if err != nil {
		return err
	}
	files := map[string]string{
		"meta-data":      metaData(vm.Instance),
		"user-data":      userData(vm.Instance),
		"network-config": networkConfig(vm.Instance, sub.Addr().Next().String(), sub.Bits()),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	tool := isoTool()
	if tool == nil {
		return errors.New("compute: need genisoimage, mkisofs or xorriso to build the cloud-init seed")
	}
	args := append(tool[1:], "-quiet", "-output", seed+".tmp", "-volid", "cidata", "-joliet", "-rock",
		filepath.Join(dir, "meta-data"), filepath.Join(dir, "user-data"), filepath.Join(dir, "network-config"))
	if err := run(ctx, tool[0], args...); err != nil {
		return err
	}
	return os.Rename(seed+".tmp", seed)
}

func isoTool() []string {
	for _, t := range [][]string{{"genisoimage"}, {"mkisofs"}, {"xorriso", "-as", "mkisofs"}} {
		if _, err := exec.LookPath(t[0]); err == nil {
			return t
		}
	}
	return nil
}

// Start boots a prepared instance.
func (q *QEMU) Start(ctx context.Context, vm *VM) error {
	if q.Running(vm) {
		return nil
	}
	t := tap(vm.Instance.ID)
	if _, err := net.InterfaceByName(t); err != nil {
		if err := run(ctx, "ip", "tuntap", "add", "dev", t, "mode", "tap"); err != nil {
			return err
		}
	}
	if err := run(ctx, "ip", "link", "set", t, "master", q.bridge(), "up"); err != nil {
		return err
	}
	in := vm.Instance
	if err := antiSpoof(ctx, t, in.PrivateIP, in.MAC); err != nil {
		return err
	}
	accel, cpu := "kvm", "host"
	if q.Emulate {
		accel, cpu = "tcg,thread=multi", "max"
	}
	os.Remove(filepath.Join(vm.Dir, "qmp.sock"))
	args := []string{
		"-name", in.ID, "-nodefaults", "-no-user-config",
		"-machine", "q35", "-accel", accel, "-cpu", cpu,
		"-smp", strconv.Itoa(in.VCPU), "-m", strconv.Itoa(in.MemMiB),
		"-drive", "file=" + filepath.Join(vm.Dir, "disk.qcow2") + ",if=virtio,format=qcow2",
		"-drive", "file=" + filepath.Join(vm.Dir, "seed.iso") + ",if=virtio,format=raw,readonly=on",
		"-netdev", "tap,id=n0,ifname=" + t + ",script=no,downscript=no",
		"-device", "virtio-net-pci,netdev=n0,mac=" + in.MAC,
		"-device", "virtio-rng-pci",
		"-display", "none",
		"-serial", "file:" + filepath.Join(vm.Dir, "console.log"),
		"-qmp", "unix:" + filepath.Join(vm.Dir, "qmp.sock") + ",server=on,wait=off",
		"-pidfile", filepath.Join(vm.Dir, "qemu.pid"),
		"-daemonize",
	}
	// Volumes go on PCIe root ports, which support hotplug (the q35 root
	// bus doesn't). Volumes attached at boot take the first ports.
	for i := 1; i <= rootPorts; i++ {
		args = append(args, "-device", fmt.Sprintf("pcie-root-port,id=rp%d,chassis=%d,bus=pcie.0", i, i))
	}
	if len(vm.Disks) > rootPorts {
		return fmt.Errorf("compute: at most %d volumes per instance", rootPorts)
	}
	for i, d := range vm.Disks {
		args = append(args,
			"-blockdev", "driver=qcow2,node-name="+nodeName(d.ID)+",file.driver=file,file.filename="+d.Path,
			"-device", volumeDevice(d.ID)+",bus="+fmt.Sprintf("rp%d", i+1)+",addr=0")
	}
	return run(ctx, q.binary(), args...)
}

// rootPorts is the number of hotplug slots, so the most volumes an
// instance can have attached.
const rootPorts = 8

// nodeName and deviceID name a volume's block node and guest device.
func nodeName(vol string) string { return "d-" + vol }
func deviceID(vol string) string { return "v-" + vol }

// volumeDevice is the virtio disk for a volume. Its serial is the volume
// ID without the dash (20 characters, virtio's limit), as on EC2's NVMe
// volumes, so the guest finds it at /dev/disk/by-id/virtio-vol....
func volumeDevice(vol string) string {
	return "virtio-blk-pci,drive=" + nodeName(vol) + ",id=" + deviceID(vol) + ",serial=" + strings.Replace(vol, "-", "", 1)
}

// CreateDisk makes a volume's qcow2: blank, or a copy of from (a
// snapshot), grown to sizeGiB.
func (q *QEMU) CreateDisk(ctx context.Context, path string, sizeGiB int, from string) error {
	size := strconv.Itoa(sizeGiB) + "G"
	if from == "" {
		return run(ctx, "qemu-img", "create", "-q", "-f", "qcow2", path, size)
	}
	if err := run(ctx, "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", from, path); err != nil {
		return err
	}
	// A volume larger than its snapshot grows; never shrink.
	_ = run(ctx, "qemu-img", "resize", "-q", path, size)
	return nil
}

// Attached lists the volumes plugged into a running VM.
func (q *QEMU) Attached(vm *VM) ([]string, error) {
	out, err := qmpRun(vm, qmpCmd{"qom-list", map[string]any{"path": "/machine/peripheral"}})
	if err != nil {
		return nil, err
	}
	var props []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out[0], &props); err != nil {
		return nil, err
	}
	var ids []string
	for _, p := range props {
		if id, ok := strings.CutPrefix(p.Name, "v-"); ok {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// Attach hotplugs a volume into a free root port.
func (q *QEMU) Attach(ctx context.Context, vm *VM, d Disk) error {
	_, err := qmpRun(vm, qmpCmd{"blockdev-add", map[string]any{
		"driver": "qcow2", "node-name": nodeName(d.ID),
		"file": map[string]any{"driver": "file", "filename": d.Path},
	}})
	if err != nil && !strings.Contains(err.Error(), "Duplicate node name") {
		return err // a node left from an earlier try is fine
	}
	for i := 1; i <= rootPorts; i++ {
		_, err = qmpRun(vm, qmpCmd{"device_add", map[string]any{
			"driver": "virtio-blk-pci", "drive": nodeName(d.ID), "id": deviceID(d.ID),
			"serial": strings.Replace(d.ID, "-", "", 1), "bus": fmt.Sprintf("rp%d", i),
			// A root port has one slot the guest scans; without this QEMU
			// would put a second device on a busy port where it's unseen.
			"addr": "0",
		}})
		if err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "not available") && !strings.Contains(err.Error(), "in use") && !strings.Contains(err.Error(), "full") {
			break
		}
	}
	_, _ = qmpRun(vm, qmpCmd{"blockdev-del", map[string]any{"node-name": nodeName(d.ID)}})
	return fmt.Errorf("compute: no free slot for %s (at most %d volumes): %w", d.ID, rootPorts, err)
}

// Detach asks the guest to release a volume and, once it has, removes it.
// The guest must cooperate (as on EC2, a volume in use may not detach
// until it is unmounted); Detach fails until it does.
func (q *QEMU) Detach(ctx context.Context, vm *VM, id string) error {
	if _, err := qmpRun(vm, qmpCmd{"device_del", map[string]any{"id": deviceID(id)}}); err != nil &&
		!strings.Contains(err.Error(), "in the process of unplug") && !strings.Contains(err.Error(), "not found") {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		ids, err := q.Attached(vm)
		if err != nil {
			return err
		}
		gone := true
		for _, a := range ids {
			if a == id {
				gone = false
			}
		}
		if gone {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("the guest has not released the volume yet")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if _, err := qmpRun(vm, qmpCmd{"blockdev-del", map[string]any{"node-name": nodeName(id)}}); err != nil &&
		!strings.Contains(err.Error(), "not found") {
		return err
	}
	return nil
}

// Capture copies a disk to a standalone qcow2 (flattening any backing
// image). A running VM is paused while it copies: pausing flushes its
// writes, so the copy is consistent as of one instant, like a power cut.
func (q *QEMU) Capture(ctx context.Context, vm *VM, src, dst string) error {
	if vm != nil && q.Running(vm) {
		if err := qmp(vm, "stop"); err != nil {
			return err
		}
		defer func() {
			if err := qmp(vm, "cont"); err != nil {
				_ = qmp(vm, "cont") // retry once; a paused guest is worse than a slow one
			}
		}()
	}
	// -U: QEMU holds a lock on the file even while paused.
	return run(ctx, "qemu-img", "convert", "-U", "-O", "qcow2", src, dst)
}

// pid returns the instance's QEMU process ID if it is running.
func pid(vm *VM) (int, bool) {
	b, err := os.ReadFile(filepath.Join(vm.Dir, "qemu.pid"))
	if err != nil {
		return 0, false
	}
	p, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || p <= 0 {
		return 0, false
	}
	cmd, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p))
	if err != nil || !bytes.Contains(cmd, []byte(vm.Instance.ID)) {
		return 0, false // gone, or the PID was reused
	}
	return p, true
}

// Running reports whether the instance's QEMU process is alive.
func (q *QEMU) Running(vm *VM) bool {
	_, ok := pid(vm)
	return ok
}

// Stop shuts the instance down: an ACPI power-off first when graceful,
// then a kill if it hasn't gone by the deadline.
func (q *QEMU) Stop(ctx context.Context, vm *VM, graceful bool) error {
	if !q.Running(vm) {
		return nil
	}
	if graceful {
		_ = qmp(vm, "system_powerdown")
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) && q.Running(vm) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	if p, ok := pid(vm); ok {
		_ = qmp(vm, "quit")
		time.Sleep(500 * time.Millisecond)
		if _, ok := pid(vm); ok {
			_ = syscall.Kill(p, syscall.SIGKILL)
		}
		for i := 0; i < 50; i++ {
			if !q.Running(vm) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil
}

// Reboot resets the instance.
func (q *QEMU) Reboot(vm *VM) error { return qmp(vm, "system_reset") }

// Destroy stops the instance and removes its tap. The caller removes its
// directory.
func (q *QEMU) Destroy(ctx context.Context, vm *VM) error {
	if err := q.Stop(ctx, vm, false); err != nil {
		return err
	}
	removeAntiSpoof(ctx, tap(vm.Instance.ID))
	if _, err := net.InterfaceByName(tap(vm.Instance.ID)); err == nil {
		return run(ctx, "ip", "link", "del", tap(vm.Instance.ID))
	}
	return nil
}

// antiSpoof stops a VM sending frames with any address but its own, so it
// can't pass itself off as another instance (the metadata service and
// other instances trust source addresses). Each tap gets an ebtables
// chain, rebuilt on every start.
func antiSpoof(ctx context.Context, tap, ip, mac string) error {
	chain := "JY-" + tap
	_ = run(ctx, "ebtables", "-N", chain, "-P", "RETURN")
	if err := run(ctx, "ebtables", "-F", chain); err != nil {
		return err
	}
	for _, rule := range [][]string{
		{"-s", "!", mac, "-j", "DROP"},
		{"-p", "ARP", "--arp-mac-src", "!", mac, "-j", "DROP"},
		{"-p", "ARP", "--arp-ip-src", "!", ip, "-j", "DROP"},
		{"-p", "IPv4", "--ip-src", "!", ip, "-j", "DROP"},
	} {
		if err := run(ctx, "ebtables", append([]string{"-A", chain}, rule...)...); err != nil {
			return err
		}
	}
	for _, hook := range []string{"INPUT", "FORWARD"} {
		for run(ctx, "ebtables", "-D", hook, "-i", tap, "-j", chain) == nil {
		}
		if err := run(ctx, "ebtables", "-A", hook, "-i", tap, "-j", chain); err != nil {
			return err
		}
	}
	return nil
}

func removeAntiSpoof(ctx context.Context, tap string) {
	chain := "JY-" + tap
	for _, hook := range []string{"INPUT", "FORWARD"} {
		for run(ctx, "ebtables", "-D", hook, "-i", tap, "-j", chain) == nil {
		}
	}
	_ = run(ctx, "ebtables", "-X", chain)
}

// qmp sends one command without arguments over the instance's QMP socket.
func qmp(vm *VM, command string) error {
	_, err := qmpRun(vm, qmpCmd{Execute: command})
	return err
}

type qmpCmd struct {
	Execute   string `json:"execute"`
	Arguments any    `json:"arguments,omitempty"`
}

// qmpRun sends commands over the instance's QMP socket and returns their
// results.
func qmpRun(vm *VM, cmds ...qmpCmd) ([]json.RawMessage, error) {
	c, err := net.DialTimeout("unix", filepath.Join(vm.Dir, "qmp.sock"), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	if _, err := r.ReadBytes('\n'); err != nil { // greeting
		return nil, err
	}
	enc := json.NewEncoder(c)
	var out []json.RawMessage
	for i, cmd := range append([]qmpCmd{{Execute: "qmp_capabilities"}}, cmds...) {
		if err := enc.Encode(cmd); err != nil {
			return nil, err
		}
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				if cmd.Execute == "quit" {
					return out, nil // QEMU exits before answering
				}
				return nil, err
			}
			var resp struct {
				Return json.RawMessage `json:"return"`
				Error  *struct {
					Desc string `json:"desc"`
				} `json:"error"`
			}
			if json.Unmarshal(line, &resp) != nil {
				continue
			}
			if resp.Error != nil {
				return nil, fmt.Errorf("qmp %s: %s", cmd.Execute, resp.Error.Desc)
			}
			if resp.Return != nil {
				if i > 0 {
					out = append(out, resp.Return)
				}
				break
			}
			// An event; keep reading.
		}
	}
	return out, nil
}

var _ Driver = (*QEMU)(nil)
