package control

import (
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

func TestClusterInstance(t *testing.T) {
	c, ami := ec2Setup(t)
	var hosts []string
	for i := 0; i < 3; i++ {
		h, _ := joinCompute(t, c, true, bigHost)
		hosts = append(hosts, h)
	}
	run := ec2meta.RunRequest{Count: 1, Template: ec2meta.Instance{ImageID: ami, Type: "jy.cluster.4x", Tags: map[string]string{"Name": "farm"}}}
	_, err := c.srv.RunInstances("alice", run)
	wantCode(t, err, ec2meta.CodeInsufficientCap)

	h4, _ := joinCompute(t, c, true, bigHost)
	hosts = append(hosts, h4)
	r, err := c.srv.RunInstances("alice", run)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Instances) != 1 {
		t.Fatalf("launched %d instances", len(r.Instances))
	}
	id := r.Instances[0].ID
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}

	// One node per PC, each told the whole cluster.
	used := map[string]bool{}
	indexes := map[int]bool{}
	for _, h := range hosts {
		v := c.srv.HostView(h)
		if len(v.Instances) != 1 {
			t.Fatalf("%s runs %d nodes", h, len(v.Instances))
		}
		n := v.Instances[0]
		if n.ClusterID() != id || n.ClusterSize != 4 || len(n.ClusterIPs) != 4 || n.ClusterIPs[n.ClusterIndex] != n.PrivateIP || n.Tags["Name"] != "farm" {
			t.Fatalf("node %+v", n)
		}
		used[h], indexes[n.ClusterIndex] = true, true
	}
	if len(used) != 4 || len(indexes) != 4 {
		t.Fatalf("hosts %v, indexes %v", used, indexes)
	}

	// The tenant sees one instance, pending until every node has started.
	list, err := c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice"})
	if err != nil || len(list) != 1 || list[0].ID != id || len(list[0].ClusterIPs) != 4 {
		t.Fatalf("instances %+v, %v", list, err)
	}
	report := func(h, state string) {
		t.Helper()
		v := c.srv.HostView(h)
		if err := c.srv.ReportInstance(h, ec2meta.StatusReport{ID: v.Instances[0].ID, State: state}); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range hosts[:3] {
		report(h, ec2meta.StateRunning)
	}
	list, _ = c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}})
	if list[0].State != ec2meta.StatePending {
		t.Fatalf("state %s with a node still starting", list[0].State)
	}
	report(hosts[3], ec2meta.StateRunning)
	list, _ = c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}})
	if list[0].State != ec2meta.StateRunning {
		t.Fatalf("state %s", list[0].State)
	}

	// The other nodes are not the tenant's to name.
	var other string
	for _, h := range hosts {
		if n := c.srv.HostView(h).Instances[0]; n.ClusterOf != "" {
			other = n.ID
		}
	}
	_, err = c.srv.InstanceAction("alice", "stop", []string{other})
	wantCode(t, err, ec2meta.CodeInvalidInstanceID)
	_, err = c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{other}})
	wantCode(t, err, ec2meta.CodeInvalidInstanceID)

	// Terminating it ends every node.
	if _, err := c.srv.InstanceAction("alice", "terminate", []string{id}); err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if n := c.srv.HostView(h).Instances[0]; n.State != ec2meta.StateShuttingDown {
			t.Fatalf("node %s is %s", n.ID, n.State)
		}
	}
	// It reads as terminated only once every node is.
	report(hosts[0], ec2meta.StateTerminated)
	list, _ = c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}})
	if list[0].State != ec2meta.StateShuttingDown {
		t.Fatalf("state %s with nodes still shutting down", list[0].State)
	}
	for _, h := range hosts[1:] {
		report(h, ec2meta.StateTerminated)
	}
	list, _ = c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}})
	if list[0].State != ec2meta.StateTerminated {
		t.Fatalf("state %s", list[0].State)
	}
}
