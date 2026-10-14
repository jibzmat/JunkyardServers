package control

import (
	"context"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

func TestVPCsSubnetsAndGroups(t *testing.T) {
	c, ami := ec2Setup(t)
	host, hc := joinCompute(t, c, true, bigHost)
	c.srv.compute = ComputeOptions{}

	def, err := c.srv.DefaultVPC("alice")
	if err != nil || def.CIDR != ec2meta.DefaultVPCCIDR || !def.IsDefault || def.VNI < firstVNI {
		t.Fatalf("default vpc %+v %v", def, err)
	}
	if again, _ := c.srv.DefaultVPC("alice"); again.ID != def.ID {
		t.Fatal("a second default VPC")
	}
	bobDef, _ := c.srv.DefaultVPC("bob")
	if bobDef.VNI == def.VNI || bobDef.CIDR != def.CIDR {
		t.Fatalf("bob's default VPC %+v", bobDef)
	}

	for _, bad := range []string{"8.8.0.0/16", "10.0.0.0/8", "10.0.0.1/16", "10.0.0.0/29"} {
		if _, err := c.srv.CreateVPC(ec2meta.VPCRequest{Tenant: "alice", CIDR: bad}); !isCode(err, ec2meta.CodeVpcRange) {
			t.Errorf("vpc %s: %v", bad, err)
		}
	}
	vpc, err := c.srv.CreateVPC(ec2meta.VPCRequest{Tenant: "alice", CIDR: "10.1.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	sn, err := c.srv.CreateSubnet(ec2meta.SubnetRequest{Tenant: "alice", VpcID: vpc.ID, CIDR: "10.1.1.0/28"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.CreateSubnet(ec2meta.SubnetRequest{Tenant: "alice", VpcID: vpc.ID, CIDR: "10.1.0.0/23"}); !isCode(err, ec2meta.CodeSubnetConflict) {
		t.Fatalf("overlapping subnet: %v", err)
	}
	if _, err := c.srv.CreateSubnet(ec2meta.SubnetRequest{Tenant: "alice", VpcID: vpc.ID, CIDR: "10.2.0.0/24"}); !isCode(err, ec2meta.CodeSubnetRange) {
		t.Fatalf("subnet outside the VPC: %v", err)
	}
	if _, err := c.srv.CreateSubnet(ec2meta.SubnetRequest{Tenant: "bob", VpcID: vpc.ID, CIDR: "10.1.2.0/24"}); !isCode(err, ec2meta.CodeVpcNotFound) {
		t.Fatalf("bob used alice's VPC: %v", err)
	}

	web, err := c.srv.CreateGroup(ec2meta.GroupRequest{Tenant: "alice", VpcID: vpc.ID, Name: "web", Description: "web servers"})
	if err != nil || len(web.Egress) != 1 || len(web.Ingress) != 0 {
		t.Fatalf("group %+v %v", web, err)
	}
	if _, err := c.srv.CreateGroup(ec2meta.GroupRequest{Tenant: "alice", VpcID: vpc.ID, Name: "web", Description: "x"}); !isCode(err, ec2meta.CodeGroupDuplicate) {
		t.Fatalf("duplicate group: %v", err)
	}
	ssh := ec2meta.Permission{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"10.9.0.0/16"}}
	if _, err := c.srv.GroupRules(ec2meta.RulesRequest{Tenant: "alice", GroupID: web.ID, Permissions: []ec2meta.Permission{ssh}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.GroupRules(ec2meta.RulesRequest{Tenant: "alice", GroupID: web.ID, Permissions: []ec2meta.Permission{ssh}}); !isCode(err, ec2meta.CodePermissionDup) {
		t.Fatalf("duplicate rule: %v", err)
	}
	// A rule may name another group of the same VPC, not of another one.
	gs, _ := c.srv.Groups(ec2meta.GroupRequest{Tenant: "alice", VpcID: vpc.ID})
	var vpcDefault string
	for _, g := range gs {
		if g.Name == ec2meta.DefaultGroupName {
			vpcDefault = g.ID
		}
	}
	fromDefault := ec2meta.Permission{Protocol: "tcp", FromPort: 80, ToPort: 80, Groups: []string{vpcDefault}}
	if _, err := c.srv.GroupRules(ec2meta.RulesRequest{Tenant: "alice", GroupID: web.ID, Permissions: []ec2meta.Permission{fromDefault}}); err != nil {
		t.Fatal(err)
	}
	defGroups, _ := c.srv.Groups(ec2meta.GroupRequest{Tenant: "alice", Names: []string{"default"}})
	if len(defGroups) != 1 || defGroups[0].VpcID != def.ID {
		t.Fatalf("groups by name: %+v", defGroups)
	}
	if _, err := c.srv.GroupRules(ec2meta.RulesRequest{Tenant: "alice", GroupID: web.ID, Permissions: []ec2meta.Permission{{Protocol: "tcp", FromPort: 1, ToPort: 2, Groups: []string{defGroups[0].ID}}}}); !isCode(err, ec2meta.CodeGroupNotFound) {
		t.Fatalf("rule naming another VPC's group: %v", err)
	}

	// Launch into the /28: 11 usable addresses.
	run := func(n int, groups ...string) ([]ec2meta.Instance, error) {
		r, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: n, Template: ec2meta.Instance{ImageID: ami, Type: "t3.nano", SubnetID: sn.ID, SecurityGroups: groups}})
		if err != nil {
			return nil, err
		}
		return r.Instances, nil
	}
	ins, err := run(2, web.ID)
	if err != nil || ins[0].PrivateIP != "10.1.1.4" || ins[1].PrivateIP != "10.1.1.5" || ins[0].VpcID != vpc.ID || ins[0].MAC == "" {
		t.Fatalf("launch %+v %v", ins, err)
	}
	if _, err := run(1, defGroups[0].ID); !isCode(err, ec2meta.CodeGroupNotFound) {
		t.Fatalf("launch with another VPC's group: %v", err)
	}
	more, err := run(9)
	if err != nil || more[8].PrivateIP != "10.1.1.14" {
		t.Fatalf("filling the subnet: %v", err)
	}
	if _, err := run(1); !isCode(err, ec2meta.CodeNoFreeAddresses) {
		t.Fatalf("full subnet: %v", err)
	}

	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	v, err := hc.HostView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Networks) != 1 {
		t.Fatalf("networks %+v", v.Networks)
	}
	// 8 of the 11 fit on the host (16 vCPUs); only placed ones are endpoints.
	n := v.Networks[0]
	if n.VPC.ID != vpc.ID || len(n.Endpoints) != 8 || n.Endpoints[0].Host != host || n.Endpoints[0].HostIP == "" {
		t.Fatalf("network %+v", n)
	}
	if len(n.Groups) != 2 || len(n.Members[vpcDefault]) != 9 {
		t.Fatalf("groups %+v members %v", n.Groups, n.Members)
	}

	// Things in use can't be deleted.
	if err := c.srv.DeleteGroup("alice", web.ID); !isCode(err, ec2meta.CodeDependency) {
		t.Fatalf("delete used group: %v", err)
	}
	if err := c.srv.DeleteSubnet("alice", sn.ID); !isCode(err, ec2meta.CodeDependency) {
		t.Fatalf("delete used subnet: %v", err)
	}
	if err := c.srv.DeleteVPC("alice", vpc.ID); !isCode(err, ec2meta.CodeDependency) {
		t.Fatalf("delete used vpc: %v", err)
	}
	if err := c.srv.DeleteGroup("alice", vpcDefault); !isCode(err, ec2meta.CodeCannotDelete) {
		t.Fatalf("delete default group: %v", err)
	}
	if _, err := c.srv.GroupRules(ec2meta.RulesRequest{Tenant: "alice", GroupID: web.ID, Revoke: true, Permissions: []ec2meta.Permission{ssh}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.GroupRules(ec2meta.RulesRequest{Tenant: "alice", GroupID: web.ID, Revoke: true, Permissions: []ec2meta.Permission{ssh}}); !isCode(err, ec2meta.CodePermissionNotFound) {
		t.Fatalf("revoke twice: %v", err)
	}
}
