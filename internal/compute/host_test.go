package compute

import (
	"context"
	"io"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

type fakeControl struct {
	mu       sync.Mutex
	view     ec2meta.HostView
	reports  []ec2meta.StatusReport
	fetches  int
	volReps  []ec2meta.VolumeReport
	failed   []ec2meta.TaskFailure
	uploads  map[string]string
	consoles map[string]string
}

func (f *fakeControl) ReportVolume(_ context.Context, r ec2meta.VolumeReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.volReps = append(f.volReps, r)
	for i := range f.view.Volumes {
		v := &f.view.Volumes[i]
		if v.ID != r.ID {
			continue
		}
		if r.Ready {
			v.Ready = true
		}
		switch r.AttachState {
		case ec2meta.AttachAttached:
			v.AttachState = r.AttachState
		case ec2meta.AttachDetached:
			v.Instance, v.Device, v.AttachState, v.State = "", "", "", ec2meta.VolumeAvailable
		}
		if r.Deleted {
			f.view.Volumes = append(f.view.Volumes[:i], f.view.Volumes[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeControl) FailTask(_ context.Context, r ec2meta.TaskFailure) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, r)
	f.dropTask(r.ID)
	return nil
}

func (f *fakeControl) UploadTask(_ context.Context, id string, open func() (io.ReadCloser, int64, error)) error {
	r, _, err := open()
	if err != nil {
		return err
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.uploads == nil {
		f.uploads = map[string]string{}
	}
	f.uploads[id] = string(b)
	f.dropTask(id)
	return nil
}

func (f *fakeControl) dropTask(id string) {
	for i, t := range f.view.Tasks {
		if t.ID == id {
			f.view.Tasks = append(f.view.Tasks[:i], f.view.Tasks[i+1:]...)
			return
		}
	}
}

func (f *fakeControl) SendConsole(_ context.Context, c ec2meta.ConsoleOutput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.consoles == nil {
		f.consoles = map[string]string{}
	}
	f.consoles[c.InstanceID] = string(c.Output)
	return nil
}

func (f *fakeControl) FetchSnapshot(_ context.Context, id string, w io.Writer) error {
	_, err := io.WriteString(w, "snapshot "+id)
	return err
}

func (f *fakeControl) HostView(context.Context) (*ec2meta.HostView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.view
	v.Instances = append([]ec2meta.Instance(nil), f.view.Instances...)
	v.Volumes = append([]ec2meta.Volume(nil), f.view.Volumes...)
	v.Tasks = append([]ec2meta.Task(nil), f.view.Tasks...)
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

var testNets = []ec2meta.VPCNet{{
	VPC:     ec2meta.VPC{ID: "vpc-1", CIDR: "10.128.0.0/16"},
	Subnets: []ec2meta.Subnet{{ID: "subnet-1", VpcID: "vpc-1", CIDR: "10.128.0.0/24"}},
}}

type fakeDriver struct {
	mu      sync.Mutex
	running map[string]bool
	network string
	reboots int
	seeds   map[string]string
	plugged map[string]map[string]bool // instance -> volumes
	booted  map[string][]string        // instance -> volumes at last boot
	stops   int
}

func (d *fakeDriver) CreateDisk(_ context.Context, path string, sizeGiB int, from string) error {
	body := "blank"
	if from != "" {
		b, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		body = string(b)
	}
	return os.WriteFile(path, []byte(body), 0o600)
}

func (d *fakeDriver) Attached(vm *VM) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var ids []string
	for id := range d.plugged[vm.Instance.ID] {
		ids = append(ids, id)
	}
	return ids, nil
}

func (d *fakeDriver) Attach(_ context.Context, vm *VM, disk Disk) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.plugged == nil {
		d.plugged = map[string]map[string]bool{}
	}
	if d.plugged[vm.Instance.ID] == nil {
		d.plugged[vm.Instance.ID] = map[string]bool{}
	}
	d.plugged[vm.Instance.ID][disk.ID] = true
	return nil
}

func (d *fakeDriver) Detach(_ context.Context, vm *VM, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.plugged[vm.Instance.ID], id)
	return nil
}

func (d *fakeDriver) Capture(_ context.Context, vm *VM, src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, append([]byte("copy of "), b...), 0o600)
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
	return os.WriteFile(filepath.Join(vm.Dir, "disk.qcow2"), []byte(image), 0o600)
}

func (d *fakeDriver) Start(_ context.Context, vm *VM) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running == nil {
		d.running = map[string]bool{}
	}
	d.running[vm.Instance.ID] = true
	if d.booted == nil {
		d.booted = map[string][]string{}
	}
	d.booted[vm.Instance.ID] = nil
	if d.plugged == nil {
		d.plugged = map[string]map[string]bool{}
	}
	d.plugged[vm.Instance.ID] = map[string]bool{}
	for _, disk := range vm.Disks {
		d.booted[vm.Instance.ID] = append(d.booted[vm.Instance.ID], disk.ID)
		d.plugged[vm.Instance.ID][disk.ID] = true
	}
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
	if d.running[vm.Instance.ID] {
		d.stops++
	}
	delete(d.running, vm.Instance.ID)
	delete(d.plugged, vm.Instance.ID)
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
	ctl := &fakeControl{view: ec2meta.HostView{Networks: testNets, Instances: []ec2meta.Instance{{
		ID: "i-0123456789abcdef0", ImageID: "ami-1", State: ec2meta.StatePending, PrivateIP: "10.128.0.10", VpcID: "vpc-1", SubnetID: "subnet-1",
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
	if !drv.running[id] || ctl.last().State != ec2meta.StateRunning {
		t.Fatalf("not started: running %v reports %+v", drv.running, ctl.reports)
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
	step := func() {
		t.Helper()
		if err := h.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		h.Wait()
	}
	// One view without it isn't enough: it might be a bad view.
	step()
	if !drv.running["i-gone"] {
		t.Fatal("destroyed on the first view without it")
	}
	h.mu.Lock()
	h.missing["i-gone"] = h.missing["i-gone"].Add(-destroyAfter)
	h.mu.Unlock()
	step()
	if drv.running["i-gone"] {
		t.Fatal("unassigned VM still running")
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "instances", "i-gone")); !os.IsNotExist(err) {
		t.Fatal("files left")
	}
}

func TestVolumesAndTasks(t *testing.T) {
	id := "i-0123456789abcdef0"
	ctl := &fakeControl{view: ec2meta.HostView{Networks: testNets,
		Instances: []ec2meta.Instance{{
			ID: id, ImageID: "ami-1", State: ec2meta.StatePending, PrivateIP: "10.128.0.10", VpcID: "vpc-1", SubnetID: "subnet-1",
			MAC: "02:00:00:00:00:01", VCPU: 1, MemMiB: 512, RootGiB: 8,
		}},
		// One volume attached before the first boot, restored from a snapshot.
		Volumes: []ec2meta.Volume{{
			ID: "vol-1", SizeGiB: 1, SnapshotID: "snap-1", State: ec2meta.VolumeInUse,
			Instance: id, Device: "/dev/sdf", AttachState: ec2meta.AttachAttaching,
		}},
	}}
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
	volume := func(vid string) ec2meta.Volume {
		ctl.mu.Lock()
		defer ctl.mu.Unlock()
		for _, v := range ctl.view.Volumes {
			if v.ID == vid {
				return v
			}
		}
		return ec2meta.Volume{}
	}

	step()
	if got := drv.booted[id]; len(got) != 1 || got[0] != "vol-1" {
		t.Fatalf("booted with %v", got)
	}
	if v := volume("vol-1"); !v.Ready || v.AttachState != ec2meta.AttachAttached {
		t.Fatalf("vol-1 %+v", v)
	}
	if b, _ := os.ReadFile(h.volumePath("vol-1")); string(b) != "snapshot snap-1" {
		t.Fatalf("vol-1 data %q", b)
	}
	ctl.set(id, ec2meta.StateRunning, 0)

	// Hotplug a blank volume into the running instance.
	ctl.mu.Lock()
	ctl.view.Volumes = append(ctl.view.Volumes, ec2meta.Volume{ID: "vol-2", SizeGiB: 2, State: ec2meta.VolumeInUse,
		Instance: id, Device: "/dev/sdg", AttachState: ec2meta.AttachAttaching})
	ctl.mu.Unlock()
	step()
	if !drv.plugged[id]["vol-2"] || volume("vol-2").AttachState != ec2meta.AttachAttached {
		t.Fatalf("vol-2 not hotplugged: %v %+v", drv.plugged[id], volume("vol-2"))
	}

	// Snapshot an attached volume, and image the instance (which stops
	// and restarts it with its volumes).
	ctl.mu.Lock()
	ctl.view.Tasks = []ec2meta.Task{
		{ID: "task-1", Kind: ec2meta.TaskSnapshot, Volume: "vol-2", Target: "snap-2"},
		{ID: "task-2", Kind: ec2meta.TaskImage, Instance: id, Target: "ami-2"},
	}
	ctl.mu.Unlock()
	step()
	if ctl.uploads["task-1"] != "copy of blank" || !strings.HasPrefix(ctl.uploads["task-2"], "copy of ") {
		t.Fatalf("uploads %v failed %v", ctl.uploads, ctl.failed)
	}
	if drv.stops != 1 || !drv.running[id] || len(drv.booted[id]) != 2 {
		t.Fatalf("imaging: stops %d running %v booted %v", drv.stops, drv.running[id], drv.booted[id])
	}

	// Detach, then delete.
	ctl.mu.Lock()
	for i := range ctl.view.Volumes {
		if ctl.view.Volumes[i].ID == "vol-2" {
			ctl.view.Volumes[i].AttachState = ec2meta.AttachDetaching
		}
	}
	ctl.mu.Unlock()
	step()
	if drv.plugged[id]["vol-2"] || volume("vol-2").Instance != "" {
		t.Fatalf("vol-2 not detached: %v %+v", drv.plugged[id], volume("vol-2"))
	}
	ctl.mu.Lock()
	for i := range ctl.view.Volumes {
		if ctl.view.Volumes[i].ID == "vol-2" {
			ctl.view.Volumes[i].State = ec2meta.VolumeDeleting
		}
	}
	ctl.mu.Unlock()
	step()
	if volume("vol-2").ID != "" {
		t.Fatal("vol-2 not deleted")
	}
	if _, err := os.Stat(h.volumePath("vol-2")); !os.IsNotExist(err) {
		t.Fatal("vol-2 data left behind")
	}

	// A task for a volume that isn't here fails rather than hanging.
	ctl.mu.Lock()
	ctl.view.Tasks = []ec2meta.Task{{ID: "task-3", Kind: ec2meta.TaskSnapshot, Volume: "vol-9", Target: "snap-9"}}
	ctl.mu.Unlock()
	step()
	if len(ctl.failed) != 1 || ctl.failed[0].ID != "task-3" {
		t.Fatalf("failed %v", ctl.failed)
	}
}

func TestMetadataService(t *testing.T) {
	h := &Host{Region: "eu-west-1"}
	m, err := newMetadataServer(h)
	if err != nil {
		t.Fatal(err)
	}
	in := ec2meta.Instance{ID: "i-0123456789abcdef0", Tenant: "alice", ImageID: "ami-1", Type: "t3.small",
		PrivateIP: "10.128.0.10", MAC: "02:00:00:00:00:01", KeyName: "me", PublicKey: "ssh-ed25519 AAAA me",
		UserData: []byte("#!/bin/sh\necho hi\n"), ReservationID: "r-1"}
	in.VpcID = "vpc-1"
	h.byIP = map[string]ec2meta.Instance{"vpc-1/" + in.PrivateIP: in}

	do := func(method, path, from string, hdr map[string]string) (int, string) {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = from + ":40000"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		m.handler("vpc-1").ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	me := in.PrivateIP
	for path, want := range map[string]string{
		"/latest/meta-data/instance-id":               in.ID,
		"/latest/meta-data/local-ipv4":                in.PrivateIP,
		"/latest/meta-data/placement/region":          "eu-west-1",
		"/latest/meta-data/public-keys/0/openssh-key": "ssh-ed25519 AAAA me\n",
		"/latest/user-data":                           "#!/bin/sh\necho hi\n",
		"/latest/meta-data/placement/":                "availability-zone\navailability-zone-id\nregion",
		"/2021-03-23/meta-data/ami-id":                "ami-1",
		"/latest/":                                    "dynamic/\nmeta-data/\nuser-data",
		"/latest/meta-data/network/interfaces/macs/":  "02:00:00:00:00:01/",
		"/latest/meta-data/public-keys/":              "0=me",
		"/latest/meta-data/public-keys/0":             "openssh-key",
	} {
		if code, body := do("GET", path, me, nil); code != 200 || body != want {
			t.Errorf("%s: %d %q, want %q", path, code, body, want)
		}
	}
	if code, body := do("GET", "/latest/meta-data/", me, nil); code != 200 || !strings.Contains(body, "instance-id\n") || !strings.Contains(body, "public-keys/") {
		t.Errorf("listing: %d %q", code, body)
	}
	if code, body := do("GET", "/latest/dynamic/instance-identity/document", me, nil); code != 200 || !strings.Contains(body, `"accountId": "`+ec2meta.AccountID("alice")+`"`) {
		t.Errorf("identity: %d %s", code, body)
	}
	if code, _ := do("GET", "/latest/meta-data/instance-id", "10.128.0.99", nil); code != 403 {
		t.Errorf("unknown address got %d", code)
	}
	if code, _ := do("GET", "/latest/meta-data/nope", me, nil); code != 404 {
		t.Errorf("missing path got %d", code)
	}

	// IMDSv2.
	code, tok := do("PUT", "/latest/api/token", me, map[string]string{tokenTTLHeader: "60"})
	if code != 200 || tok == "" {
		t.Fatalf("token: %d %q", code, tok)
	}
	if code, body := do("GET", "/latest/meta-data/instance-id", me, map[string]string{tokenHeader: tok}); code != 200 || body != in.ID {
		t.Errorf("with token: %d %q", code, body)
	}
	if code, _ := do("GET", "/latest/meta-data/instance-id", me, map[string]string{tokenHeader: tok + "x"}); code != 401 {
		t.Errorf("bad token got %d", code)
	}
	other := in
	other.ID, other.PrivateIP = "i-other", "10.128.0.11"
	h.byIP["vpc-1/"+other.PrivateIP] = other
	if code, _ := do("GET", "/latest/meta-data/instance-id", other.PrivateIP, map[string]string{tokenHeader: tok}); code != 401 {
		t.Errorf("another instance's token got %d", code)
	}
	if code, _ := do("PUT", "/latest/api/token", me, nil); code != 400 {
		t.Errorf("token without TTL got %d", code)
	}
	if code, _ := do("PUT", "/latest/api/token", me, map[string]string{tokenTTLHeader: "60", "X-Forwarded-For": "1.2.3.4"}); code != 403 {
		t.Errorf("proxied token request got %d", code)
	}
}
