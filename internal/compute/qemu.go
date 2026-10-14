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
	for _, b := range []string{q.binary(), "qemu-img", "ip", "iptables"} {
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
	return run(ctx, q.binary(), args...)
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
	if _, err := net.InterfaceByName(tap(vm.Instance.ID)); err == nil {
		return run(ctx, "ip", "link", "del", tap(vm.Instance.ID))
	}
	return nil
}

// qmp sends one command over the instance's QMP socket.
func qmp(vm *VM, command string) error {
	c, err := net.DialTimeout("unix", filepath.Join(vm.Dir, "qmp.sock"), 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	if _, err := r.ReadBytes('\n'); err != nil { // greeting
		return err
	}
	enc := json.NewEncoder(c)
	for _, cmd := range []string{"qmp_capabilities", command} {
		if err := enc.Encode(map[string]string{"execute": cmd}); err != nil {
			return err
		}
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				if cmd == "quit" {
					return nil // QEMU exits before answering
				}
				return err
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
				return fmt.Errorf("qmp %s: %s", cmd, resp.Error.Desc)
			}
			if resp.Return != nil {
				break
			}
			// An event; keep reading.
		}
	}
	return nil
}

var _ Driver = (*QEMU)(nil)
