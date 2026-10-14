package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/hw"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
)

// joinCompute joins a compute host and returns its ID and a client using
// its certificate.
func joinCompute(t *testing.T, c *testCluster, trusted bool, h hw.Info) (string, *Client) {
	t.Helper()
	req, keys := joinReq(t, cluster.RoleCompute)
	req.Hardware = h
	resp, err := Join(context.Background(), c.token(t, trusted), req)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(resp.CertPEM)
	return resp.NodeID, NewClient([]string{c.addr}, pki.TLSCertificate(cert.Raw, keys.Signing, c.srv.CA()), c.srv.CA())
}

var bigHost = hw.Info{Cores: 4, MemBytes: 16 << 30, KVM: true}

func ec2Setup(t *testing.T) (*testCluster, string) {
	t.Helper()
	c := newTestCluster(t)
	if _, err := c.srv.CreateTenant("alice"); err != nil {
		t.Fatal(err)
	}
	img, err := c.srv.PutImage("alice", ec2meta.Image{Name: "ubuntu", Format: "qcow2", Size: 5},
		s3meta.Object{ID: "seg-1", Size: 5, WrappedKey: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	return c, img.ID
}

func TestRunInstancesSchedulesAndHostReports(t *testing.T) {
	c, ami := ec2Setup(t)
	host, hc := joinCompute(t, c, true, bigHost)
	c.srv.StartCompute(ComputeOptions{})

	if err := c.srv.PutKeyPair("alice", ec2meta.KeyPair{Name: "k", PublicKey: "ssh-ed25519 AAAA test"}); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.PutKeyPair("alice", ec2meta.KeyPair{Name: "k", PublicKey: "x"}); !isCode(err, ec2meta.CodeKeyPairDuplicate) {
		t.Fatalf("duplicate key pair: %v", err)
	}
	resp, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 2, Template: ec2meta.Instance{ImageID: ami, Type: "t3.micro", KeyName: "k"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Instances) != 2 || resp.Instances[0].State != ec2meta.StatePending || resp.Instances[0].PublicKey == "" {
		t.Fatalf("%+v", resp.Instances)
	}
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	v, err := hc.HostView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Networks) != 1 || len(v.Networks[0].Endpoints) != 2 || v.Networks[0].VPC.CIDR != ec2meta.DefaultVPCCIDR || len(v.Instances) != 2 {
		t.Fatalf("host view %+v", v)
	}
	ips := map[string]bool{}
	for _, in := range v.Instances {
		if in.Host != host || in.MAC == "" {
			t.Fatalf("instance %+v", in)
		}
		ips[in.PrivateIP] = true
	}
	// The default subnet's first four addresses are reserved.
	if !ips["172.31.0.4"] || !ips["172.31.0.5"] {
		t.Fatalf("ips %v", ips)
	}
	id := v.Instances[0].ID
	if err := hc.ReportInstance(context.Background(), ec2meta.StatusReport{ID: id, State: ec2meta.StateRunning}); err != nil {
		t.Fatal(err)
	}
	// A host can't report what isn't a host's to decide.
	if err := hc.ReportInstance(context.Background(), ec2meta.StatusReport{ID: id, State: ec2meta.StateTerminated}); err == nil {
		t.Fatal("host terminated a running instance on its own")
	}
	ch, err := c.srv.InstanceAction("alice", "stop", []string{id})
	if err != nil || ch.Changes[0].Previous != ec2meta.StateRunning || ch.Changes[0].Current != ec2meta.StateStopping {
		t.Fatalf("stop: %+v %v", ch, err)
	}
	if _, err := c.srv.InstanceAction("alice", "reboot", []string{id}); !isCode(err, ec2meta.CodeIncorrectState) {
		t.Fatalf("reboot while stopping: %v", err)
	}
	if err := hc.ReportInstance(context.Background(), ec2meta.StatusReport{ID: id, State: ec2meta.StateStopped}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.InstanceAction("alice", "start", []string{id}); err != nil {
		t.Fatal(err)
	}
	ch, err = c.srv.InstanceAction("alice", "terminate", []string{id})
	if err != nil || ch.Changes[0].Current != ec2meta.StateShuttingDown {
		t.Fatalf("terminate: %+v %v", ch, err)
	}
	if err := hc.ReportInstance(context.Background(), ec2meta.StatusReport{ID: id, State: ec2meta.StateTerminated}); err != nil {
		t.Fatal(err)
	}
	// Other tenants see nothing.
	if _, err := c.srv.Instances(ec2meta.InstancesRequest{Tenant: "bob", IDs: []string{id}}); !isCode(err, ec2meta.CodeInvalidInstanceID) {
		t.Fatalf("bob sees alice's instance: %v", err)
	}
	// Terminated instances are purged after an hour.
	c.srv.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}}); err == nil {
		t.Fatal("terminated instance not purged")
	}
}

func TestPlacementAndCapacity(t *testing.T) {
	c, ami := ec2Setup(t)
	stranger, _ := joinCompute(t, c, false, bigHost)
	c.srv.StartCompute(ComputeOptions{})
	run := func(typ, placement string) (*ec2meta.RunResponse, error) {
		return c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 1, Template: ec2meta.Instance{ImageID: ami, Type: typ, Placement: placement}})
	}
	// The only host is a stranger's: private (the default) can't run.
	if _, err := run("t3.micro", ""); !isCode(err, ec2meta.CodeInsufficientCap) {
		t.Fatalf("private on a stranger's PC: %v", err)
	}
	if _, err := run("t3.micro", ec2meta.PlacementConfidential); !isCode(err, ec2meta.CodeInsufficientCap) {
		t.Fatalf("confidential without SEV/TDX: %v", err)
	}
	// Too big for any host.
	if _, err := run("r5.xlarge", ec2meta.PlacementAny); !isCode(err, ec2meta.CodeInsufficientCap) {
		t.Fatalf("32 GiB on a 16 GiB host: %v", err)
	}
	var ids []string
	for i := 0; i < 2; i++ {
		r, err := run("t3.large", ec2meta.PlacementAny) // 8 GiB each; 15 fit
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.Instances[0].ID)
	}
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	got, _ := c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: ids})
	if got[0].Host != stranger || got[1].Host != "" {
		t.Fatalf("hosts %q %q: the second shouldn't fit", got[0].Host, got[1].Host)
	}
	// Terminating the first frees room once the host confirms.
	c.srv.InstanceAction("alice", "terminate", ids[:1])
	c.srv.ReportInstance(stranger, ec2meta.StatusReport{ID: ids[0], State: ec2meta.StateTerminated})
	c.srv.schedule()
	got, _ = c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: ids[1:]})
	if got[0].Host != stranger {
		t.Fatal("second instance not placed after the first was terminated")
	}
}

func TestLostHostReleasesInstances(t *testing.T) {
	c, ami := ec2Setup(t)
	host, _ := joinCompute(t, c, true, bigHost)
	alive := true
	// No scheduler loop: the test drives schedule() and changes the clock.
	c.srv.compute = ComputeOptions{Alive: func() map[string]bool { return map[string]bool{host: alive} }}
	r, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 1, Template: ec2meta.Instance{ImageID: ami, Type: "t3.micro"}})
	if err != nil {
		t.Fatal(err)
	}
	id := r.Instances[0].ID
	c.srv.schedule()
	alive = false
	c.srv.now = func() time.Time { return time.Now().Add(time.Hour) }
	c.srv.schedule()
	got, _ := c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}})
	if got[0].Host != "" || got[0].State != ec2meta.StatePending {
		t.Fatalf("pending instance still on a lost host: %+v", got[0])
	}
}

func TestImagesAreObjectsInAHiddenBucket(t *testing.T) {
	c, ami := ec2Setup(t)
	if bs := c.srv.ListBuckets("alice"); len(bs) != 0 {
		t.Fatalf("image bucket visible: %v", bs)
	}
	found := false
	for _, o := range c.srv.AllObjects() {
		if o.Bucket == imageBucket && o.Key == ami && o.ID == "seg-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("image bytes not covered by repair")
	}
	if _, err := c.srv.Images(ec2meta.ImageRequest{Tenant: "bob", IDs: []string{ami}}); !isCode(err, ec2meta.CodeInvalidAMIID) {
		t.Fatalf("bob sees alice's image: %v", err)
	}
	old, err := c.srv.DeleteImage("alice", ami)
	if err != nil || old == nil || old.ID != "seg-1" {
		t.Fatalf("delete: %+v %v", old, err)
	}
}

func isCode(err error, code string) bool {
	var e *s3meta.Error
	return errors.As(err, &e) && e.Code == code
}
