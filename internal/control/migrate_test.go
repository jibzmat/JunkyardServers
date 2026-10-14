package control

import (
	"context"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

func TestMigrateAndDrain(t *testing.T) {
	c, ami := ec2Setup(t)
	h1, c1 := joinCompute(t, c, true, bigHost)
	h2, c2 := joinCompute(t, c, true, bigHost)
	clients := map[string]*Client{h1: c1, h2: c2}
	c.srv.compute = ComputeOptions{Alive: func() map[string]bool { return map[string]bool{h1: true, h2: true} }}
	get := func(id string) ec2meta.Instance {
		t.Helper()
		got, err := c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}})
		if err != nil {
			t.Fatal(err)
		}
		return got[0]
	}
	r, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 1, Template: ec2meta.Instance{ImageID: ami, Type: "t3.micro"}})
	if err != nil {
		t.Fatal(err)
	}
	id := r.Instances[0].ID
	c.srv.schedule()
	c.srv.schedule()
	in := get(id)
	src, dst := in.Host, in.Replica
	ctx := context.Background()
	if err := clients[src].ReportInstance(ctx, ec2meta.StatusReport{ID: id, State: ec2meta.StateRunning}); err != nil {
		t.Fatal(err)
	}
	vol, err := c.srv.CreateVolume("alice", ec2meta.Volume{SizeGiB: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.AttachVolume(ec2meta.AttachRequest{Tenant: "alice", Volume: vol.ID, Instance: id, Device: "/dev/sdf"}); err != nil {
		t.Fatal(err)
	}
	if err := clients[src].ReportReplica(ctx, ec2meta.ReplicaReport{Instance: id, Replica: dst, Synced: true, Volumes: []string{vol.ID}}); err != nil {
		t.Fatal(err)
	}

	// Migrate to the replica (the default target).
	got, err := c.srv.Migrate(ec2meta.MigrateRequest{Instance: id})
	if err != nil {
		t.Fatal(err)
	}
	if got.MigrateTo != dst || !got.ReplicaSynced {
		t.Fatalf("after migrate: %+v", got)
	}
	if v := c.srv.HostView(dst); len(v.Incoming) != 1 || v.Incoming[0].ID != id || len(v.Networks) == 0 {
		t.Fatalf("target's view: incoming %+v, networks %d", v.Incoming, len(v.Networks))
	}
	done := ec2meta.MigrationReport{Instance: id, To: dst, OK: true}
	if err := clients[dst].ReportMigration(ctx, done); err == nil {
		t.Fatal("the target reported the migration")
	}
	if err := clients[src].ReportMigration(ctx, done); err != nil {
		t.Fatal(err)
	}
	got2 := get(id)
	if got2.Host != dst || got2.MigrateTo != "" || got2.Replica != "" || got2.State != ec2meta.StateRunning || got2.Recovered {
		t.Fatalf("after migrating: %+v", got2)
	}
	vols, _ := c.srv.Volumes(ec2meta.VolumeRequest{Tenant: "alice", IDs: []string{vol.ID}})
	if vols[0].Host != dst || vols[0].Instance != id {
		t.Fatalf("volume after migrating: %+v", vols[0])
	}

	// Draining dst sends it back to src, its new replica.
	c.srv.schedule()
	if err := clients[dst].ReportReplica(ctx, ec2meta.ReplicaReport{Instance: id, Replica: src, Synced: true, Volumes: []string{vol.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.Migrate(ec2meta.MigrateRequest{Drain: dst}); err != nil {
		t.Fatal(err)
	}
	c.srv.schedule()
	if got := get(id); got.MigrateTo != src {
		t.Fatalf("draining: %+v", got)
	}
	// A failed migration leaves it in place, and draining tries again.
	if err := clients[dst].ReportMigration(ctx, ec2meta.MigrationReport{Instance: id, To: src, Reason: "no"}); err != nil {
		t.Fatal(err)
	}
	if got := get(id); got.Host != dst || got.MigrateTo != "" {
		t.Fatalf("after a failed migration: %+v", got)
	}
	c.srv.schedule()
	if got := get(id); got.MigrateTo != src {
		t.Fatalf("draining again: %+v", got)
	}
	// Nothing new lands on a drained PC.
	r2, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 3, Template: ec2meta.Instance{ImageID: ami, Type: "t3.micro"}})
	if err != nil {
		t.Fatal(err)
	}
	c.srv.schedule()
	c.srv.schedule()
	for _, x := range r2.Instances {
		if got := get(x.ID); got.Host == dst || got.Replica == dst {
			t.Fatalf("placed on the drained PC: %+v", got)
		}
	}
	if _, err := c.srv.Migrate(ec2meta.MigrateRequest{Undrain: dst}); err != nil {
		t.Fatal(err)
	}
	c.srv.schedule()
	if got := get(r2.Instances[0].ID); got.Replica != dst {
		t.Fatalf("undrained PC not used for replicas: %+v", got)
	}
}
