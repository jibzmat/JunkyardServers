package compute

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

type fakeControl struct {
	mu      sync.Mutex
	view    ec2meta.HostView
	reports []ec2meta.StatusReport
	fetches int
}

func (f *fakeControl) HostView(context.Context) (*ec2meta.HostView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.view
	v.Instances = append([]ec2meta.Instance(nil), f.view.Instances...)
	return &v, nil
}

func (f *fakeControl) ReportInstance(_ context.Context, r ec2meta.StatusReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, r)
	for i := range f.view.Instances {
		if f.view.Instances[i].ID == r.ID {
			f.view.Instances[i].State = r.State
		}
	}
	return nil
}

func (f *fakeControl) FetchImage(_ context.Context, id string, w io.Writer) (string, error) {
	f.mu.Lock()
	f.fetches++
	f.mu.Unlock()
	_, err := io.WriteString(w, "image "+id)
	return "raw", err
}

func (f *fakeControl) set(id, state string, seq int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.view.Instances {
		if f.view.Instances[i].ID == id {
			f.view.Instances[i].State = state
			f.view.Instances[i].RebootSeq = seq
		}
	}
}

func (f *fakeControl) last() ec2meta.StatusReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reports[len(f.reports)-1]
}

type fakeDriver struct {
	mu      sync.Mutex
	running map[string]bool
	network string
	reboots int
	seeds   map[string]string
}

func (d *fakeDriver) Network(_ context.Context, p netip.Prefix) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.network = p.String()
	return nil
}

func (d *fakeDriver) ConvertImage(_ context.Context, src, format, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

func (d *fakeDriver) Prepare(_ context.Context, vm *VM, image string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seeds == nil {
		d.seeds = map[string]string{}
	}
	sub, _ := netip.ParsePrefix(vm.Subnet)
	d.seeds[vm.Instance.ID] = metaData(vm.Instance) + userData(vm.Instance) + networkConfig(vm.Instance, sub.Addr().Next().String(), sub.Bits())
	return os.WriteFile(filepath.Join(vm.Dir, "disk"), []byte(image), 0o600)
}

func (d *fakeDriver) Start(_ context.Context, vm *VM) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running == nil {
		d.running = map[string]bool{}
	}
	d.running[vm.Instance.ID] = true
	return nil
}

func (d *fakeDriver) Running(vm *VM) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running[vm.Instance.ID]
}

func (d *fakeDriver) Stop(_ context.Context, vm *VM, _ bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.running, vm.Instance.ID)
	return nil
}

func (d *fakeDriver) Reboot(*VM) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reboots++
	return nil
}

func (d *fakeDriver) Destroy(ctx context.Context, vm *VM) error { return d.Stop(ctx, vm, false) }

func TestHostLifecycle(t *testing.T) {
	ctl := &fakeControl{view: ec2meta.HostView{Subnet: "10.128.0.0/24", Instances: []ec2meta.Instance{{
		ID: "i-0123456789abcdef0", ImageID: "ami-1", State: ec2meta.StatePending, PrivateIP: "10.128.0.10",
		MAC: "02:00:00:00:00:01", PublicKey: "ssh-ed25519 AAAA k", VCPU: 2, MemMiB: 1024, RootGiB: 8,
	}}}}
	drv := &fakeDriver{}
	h := &Host{Control: ctl, Driver: drv, Dir: t.TempDir()}
	ctx := context.Background()
	step := func() {
		t.Helper()
		if err := h.Step(ctx); err != nil {
			t.Fatal(err)
		}
		h.Wait()
	}
	id := "i-0123456789abcdef0"

	step()
	if drv.network != "10.128.0.0/24" || !drv.running[id] || ctl.last().State != ec2meta.StateRunning {
		t.Fatalf("not started: net %q running %v reports %+v", drv.network, drv.running, ctl.reports)
	}
	seed := drv.seeds[id]
	for _, want := range []string{"instance-id: " + id, "ssh-ed25519 AAAA k", "10.128.0.10/24", "via: 10.128.0.1", "02:00:00:00:00:01"} {
		if !strings.Contains(seed, want) {
			t.Fatalf("seed lacks %q:\n%s", want, seed)
		}
	}

	// Reboot once per request, not on every pass.
	ctl.set(id, ec2meta.StateRunning, 1)
	step()
	step()
	if drv.reboots != 1 {
		t.Fatalf("reboots %d", drv.reboots)
	}

	// The guest powers itself off: reported stopped.
	drv.Stop(ctx, &VM{Instance: ec2meta.Instance{ID: id}}, false)
	step()
	if r := ctl.last(); r.State != ec2meta.StateStopped || !strings.Contains(r.Reason, "InstanceInitiatedShutdown") {
		t.Fatalf("report %+v", r)
	}

	// Start again: the image is not fetched twice.
	ctl.set(id, ec2meta.StatePending, 1)
	step()
	if !drv.running[id] || ctl.fetches != 1 {
		t.Fatalf("restart: running %v fetches %d", drv.running[id], ctl.fetches)
	}

	ctl.set(id, ec2meta.StateStopping, 1)
	step()
	if drv.running[id] || ctl.last().State != ec2meta.StateStopped {
		t.Fatal("not stopped")
	}

	ctl.set(id, ec2meta.StateShuttingDown, 1)
	step()
	if ctl.last().State != ec2meta.StateTerminated {
		t.Fatal("not terminated")
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "instances", id)); !os.IsNotExist(err) {
		t.Fatal("instance files left behind")
	}
}

func TestUnassignedVMsAreDestroyed(t *testing.T) {
	ctl := &fakeControl{}
	drv := &fakeDriver{running: map[string]bool{"i-gone": true}}
	h := &Host{Control: ctl, Driver: drv, Dir: t.TempDir()}
	os.MkdirAll(filepath.Join(h.Dir, "instances", "i-gone"), 0o700)
	if err := h.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.Wait()
	if drv.running["i-gone"] {
		t.Fatal("unassigned VM still running")
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "instances", "i-gone")); !os.IsNotExist(err) {
		t.Fatal("files left")
	}
}
