package control

import (
	"context"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

func TestAuditsSuspendAndReinstate(t *testing.T) {
	c := newTestCluster(t)
	req, _ := joinReq(t, cluster.RoleStorage, cluster.RoleCompute)
	req.Hardware = bigHost
	resp, err := Join(context.Background(), c.token(t, false), req)
	if err != nil {
		t.Fatal(err)
	}
	id := resp.NodeID
	member := func() cluster.Member {
		t.Helper()
		for _, m := range c.srv.Members() {
			if m.NodeID == id {
				return m
			}
		}
		t.Fatal("member gone")
		return cluster.Member{}
	}
	record := func(ok bool) {
		t.Helper()
		if err := c.srv.RecordAudits([]storage.AuditResult{{Node: id, Hash: "h", OK: ok}}); err != nil {
			t.Fatal(err)
		}
	}
	record(false)
	if a := member().Audits; a.Failed != 1 || a.Score != 0.25 || a.Suspended {
		t.Fatalf("after one failure: %+v", a)
	}
	record(false)
	m := member()
	if !m.Audits.Suspended {
		t.Fatalf("not suspended: %+v", m.Audits)
	}
	if c.srv.eligible(&m, ec2Any(), true) {
		t.Fatal("a suspended PC may run instances")
	}
	// Passing audits brings it back, slowly.
	passes := 0
	for member().Audits.Suspended {
		record(true)
		passes++
		if passes > 20 {
			t.Fatal("never reinstated")
		}
	}
	if passes < 3 {
		t.Fatalf("reinstated after only %d passes", passes)
	}
	m = member()
	if !c.srv.eligible(&m, ec2Any(), true) {
		t.Fatal("reinstated PC still can't run instances")
	}
	// Unknown nodes are ignored.
	if err := c.srv.RecordAudits([]storage.AuditResult{{Node: "n-nobody", OK: false}}); err != nil {
		t.Fatal(err)
	}
}

func ec2Any() ec2meta.Instance { return ec2meta.Instance{Placement: ec2meta.PlacementAny} }
