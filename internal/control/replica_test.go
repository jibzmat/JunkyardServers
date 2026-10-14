package control

import (
	"context"
	"testing"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

func TestReplicasAndFailover(t *testing.T) {
	c, ami := ec2Setup(t)
	h1, c1 := joinCompute(t, c, true, bigHost)
	h2, c2 := joinCompute(t, c, true, bigHost)
	clients := map[string]*Client{h1: c1, h2: c2}
	alive := map[string]bool{h1: true, h2: true}
	// No scheduler loop: the test drives schedule() and the clock.
	c.srv.compute = ComputeOptions{Alive: func() map[string]bool {
		m := map[string]bool{}
		for k, v := range alive {
			m[k] = v
		}
		return m
	}}
	start := time.Now()
	c.srv.now = func() time.Time { return start }
	get := func(id string) ec2meta.Instance {
		t.Helper()
		got, err := c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}})
		if err != nil {
			t.Fatal(err)
		}
		return got[0]
	}
	r, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 2, Template: ec2meta.Instance{ImageID: ami, Type: "t3.micro"}})
	if err != nil {
		t.Fatal(err)
	}
	synced, unsynced := r.Instances[0].ID, r.Instances[1].ID
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.schedule(); err != nil { // replicas are picked once placed
		t.Fatal(err)
	}
	in := get(synced)
	if in.Host == "" || in.Replica == "" || in.Host == in.Replica {
		t.Fatalf("host %q, replica %q", in.Host, in.Replica)
	}
	primary, replica := in.Host, in.Replica
	if v := c.srv.HostView(replica); len(v.Replicas) == 0 {
		t.Fatalf("replica's view lists no copies: %+v", v.Replicas)
	}
	ctx := context.Background()
	for _, id := range []string{synced, unsynced} {
		x := get(id)
		if err := clients[x.Host].ReportInstance(ctx, ec2meta.StatusReport{ID: id, State: ec2meta.StateRunning}); err != nil {
			t.Fatal(err)
		}
	}

	vol, err := c.srv.CreateVolume("alice", ec2meta.Volume{SizeGiB: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.AttachVolume(ec2meta.AttachRequest{Tenant: "alice", Volume: vol.ID, Instance: synced, Device: "/dev/sdf"}); err != nil {
		t.Fatal(err)
	}
	if err := clients[primary].ReportVolume(ctx, ec2meta.VolumeReport{ID: vol.ID, Ready: true, AttachState: ec2meta.AttachAttached}); err != nil {
		t.Fatal(err)
	}

	// Only the primary reports, and only about the current replica.
	rep := ec2meta.ReplicaReport{Instance: synced, Replica: replica, Synced: true, Volumes: []string{vol.ID}}
	if err := clients[replica].ReportReplica(ctx, rep); err == nil {
		t.Fatal("the replica reported for its primary")
	}
	if err := clients[primary].ReportReplica(ctx, ec2meta.ReplicaReport{Instance: synced, Replica: "elsewhere", Synced: true}); err == nil {
		t.Fatal("report about another replica accepted")
	}
	if err := clients[primary].ReportReplica(ctx, rep); err != nil {
		t.Fatal(err)
	}
	if !get(synced).ReplicaSynced {
		t.Fatal("not marked synced")
	}

	// The primary is lost. Nothing moves until it has been gone a while.
	alive[primary] = false
	c.srv.schedule()
	if got := get(synced); got.Host != primary {
		t.Fatalf("moved at once: %+v", got)
	}
	c.srv.now = func() time.Time { return start.Add(hostLostAfter + time.Minute) }
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	got := get(synced)
	if got.Host != replica || got.State != ec2meta.StatePending || !got.Recovered || got.StateReason != failoverReason {
		t.Fatalf("after failover: %+v", got)
	}
	if got.Replica != "" {
		t.Fatalf("replica %q is the lost PC or the host itself", got.Replica)
	}
	vols, _ := c.srv.Volumes(ec2meta.VolumeRequest{Tenant: "alice", IDs: []string{vol.ID}})
	if vols[0].Host != replica || vols[0].Instance != synced {
		t.Fatalf("volume after failover: %+v", vols[0])
	}

	// An instance whose copy wasn't in step stays put (its data is only
	// on the lost PC).
	if x := get(unsynced); x.Host == h1 && !alive[h1] || x.Host == h2 && !alive[h2] {
		if x.Recovered {
			t.Fatalf("moved without a copy: %+v", x)
		}
	}

	// The PC comes back and becomes the new replica.
	alive[primary] = true
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	if got := get(synced); got.Replica != primary || got.ReplicaSynced {
		t.Fatalf("new replica: %+v", got)
	}
}
