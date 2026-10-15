package control

import (
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

func TestNatGateway(t *testing.T) {
	c, ami := ec2Setup(t)
	h1, _ := joinCompute(t, c, true, bigHost)
	gw, _ := joinCompute(t, c, true, bigHost)
	c.srv.compute = ComputeOptions{Alive: func() map[string]bool { return map[string]bool{h1: true} }}
	if err := c.srv.Pool(ec2meta.PoolRequest{Node: gw, IPs: []string{"203.0.113.11"}}); err != nil {
		t.Fatal(err)
	}
	vpc, err := c.srv.DefaultVPC("alice")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := c.srv.Subnets(ec2meta.SubnetRequest{Tenant: "alice"})
	if err != nil || len(pub) == 0 {
		t.Fatal(pub, err)
	}
	priv, err := c.srv.CreateSubnet(ec2meta.SubnetRequest{Tenant: "alice", VpcID: vpc.ID, CIDR: "172.31.128.0/20"})
	if err != nil {
		t.Fatal(err)
	}

	// The main table is there from the start, routed to the internet gateway.
	ts, err := c.srv.RouteTables(ec2meta.RouteRequest{Tenant: "alice"})
	if err != nil || len(ts) != 1 || !ts[0].Main || ts[0].Routes[0].Gateway != ec2meta.InternetGateway(vpc.ID) {
		t.Fatalf("tables %+v, %v", ts, err)
	}
	main := ts[0].ID

	a, err := c.srv.AllocateAddress(ec2meta.AddressRequest{Tenant: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	nat, err := c.srv.CreateNatGateway(ec2meta.RouteRequest{Tenant: "alice", SubnetID: pub[0].ID, AllocationID: a.AllocationID})
	if err != nil {
		t.Fatal(err)
	}
	if nat.PublicIP != "203.0.113.11" || nat.State != ec2meta.NatAvailable {
		t.Fatalf("nat %+v", nat)
	}
	// Its address is the gateway's now.
	_, err = c.srv.CreateNatGateway(ec2meta.RouteRequest{Tenant: "alice", SubnetID: pub[0].ID, AllocationID: a.AllocationID})
	wantCode(t, err, ec2meta.CodeAddressInUse)
	err = c.srv.ReleaseAddress(ec2meta.AddressRequest{Tenant: "alice", AllocationIDs: []string{a.AllocationID}})
	wantCode(t, err, ec2meta.CodeAddressInUse)

	rt, err := c.srv.CreateRouteTable(ec2meta.RouteRequest{Tenant: "alice", VpcID: vpc.ID})
	if err != nil {
		t.Fatal(err)
	}
	route := &ec2meta.Route{Destination: ec2meta.DefaultRoute, NatGateway: nat.ID}
	if err := c.srv.SetRoute(ec2meta.RouteRequest{Tenant: "alice", TableID: rt.ID, Route: route}); err != nil {
		t.Fatal(err)
	}
	err = c.srv.SetRoute(ec2meta.RouteRequest{Tenant: "alice", TableID: rt.ID, Route: route})
	wantCode(t, err, ec2meta.CodeRouteExists)
	err = c.srv.SetRoute(ec2meta.RouteRequest{Tenant: "alice", TableID: rt.ID, Route: &ec2meta.Route{Destination: "10.9.0.0/16", NatGateway: nat.ID}})
	wantCode(t, err, ec2meta.CodeInvalidParameter)
	assoc, err := c.srv.AssociateRouteTable(ec2meta.RouteRequest{Tenant: "alice", TableID: rt.ID, SubnetID: priv.ID})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 1, Template: ec2meta.Instance{ImageID: ami, Type: "t3.micro", SubnetID: priv.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	// The NAT gateway's PC joins the VPC, and both learn the subnet's way out.
	for _, node := range []string{h1, gw} {
		v := c.srv.HostView(node)
		if len(v.Networks) != 1 || len(v.Networks[0].Egress) != 1 {
			t.Fatalf("%s's view: %+v", node, v.Networks)
		}
		e := v.Networks[0].Egress[0]
		if e.CIDR != priv.CIDR || e.None || e.PublicIP != "203.0.113.11" || e.Gateway != gw || e.GatewayIP == "" {
			t.Fatalf("egress %+v", e)
		}
	}

	// Dependencies.
	wantCode(t, c.srv.DeleteRouteTable(ec2meta.RouteRequest{Tenant: "alice", TableID: rt.ID}), ec2meta.CodeDependency)
	wantCode(t, c.srv.DeleteRouteTable(ec2meta.RouteRequest{Tenant: "alice", TableID: main}), ec2meta.CodeDependency)
	wantCode(t, c.srv.DeleteSubnet("alice", pub[0].ID), ec2meta.CodeDependency)

	// Deleting the gateway blackholes the route: no internet for the subnet.
	if _, err := c.srv.DeleteNatGateway(ec2meta.RouteRequest{Tenant: "alice", IDs: []string{nat.ID}}); err != nil {
		t.Fatal(err)
	}
	v := c.srv.HostView(h1)
	if len(v.Networks) != 1 || len(v.Networks[0].Egress) != 1 || !v.Networks[0].Egress[0].None {
		t.Fatalf("after deleting: %+v", v.Networks)
	}
	if v := c.srv.HostView(gw); len(v.Networks) != 0 {
		t.Fatalf("NAT PC still in the VPC: %+v", v.Networks)
	}
	if err := c.srv.ReleaseAddress(ec2meta.AddressRequest{Tenant: "alice", AllocationIDs: []string{a.AllocationID}}); err != nil {
		t.Fatal(err)
	}
	// Back to the internet gateway.
	if err := c.srv.SetRoute(ec2meta.RouteRequest{Tenant: "alice", TableID: rt.ID, Replace: true,
		Route: &ec2meta.Route{Destination: ec2meta.DefaultRoute, Gateway: ec2meta.InternetGateway(vpc.ID)}}); err != nil {
		t.Fatal(err)
	}
	if v := c.srv.HostView(h1); len(v.Networks[0].Egress) != 0 {
		t.Fatalf("egress %+v", v.Networks[0].Egress)
	}
	if err := c.srv.DisassociateRouteTable(ec2meta.RouteRequest{Tenant: "alice", AssociationID: assoc}); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.DeleteRouteTable(ec2meta.RouteRequest{Tenant: "alice", TableID: rt.ID}); err != nil {
		t.Fatal(err)
	}
	// Bob sees none of it.
	if _, err := c.srv.CreateTenant("bob"); err != nil {
		t.Fatal(err)
	}
	_, err = c.srv.RouteTables(ec2meta.RouteRequest{Tenant: "bob", IDs: []string{main}})
	wantCode(t, err, ec2meta.CodeRouteTableNotFound)
}
