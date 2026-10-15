package control

import (
	"errors"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
)

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var me *s3meta.Error
	if !errors.As(err, &me) || me.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestElasticIPs(t *testing.T) {
	c, ami := ec2Setup(t)
	h1, _ := joinCompute(t, c, true, bigHost)
	gw, _ := joinCompute(t, c, true, bigHost)
	c.srv.compute = ComputeOptions{Alive: func() map[string]bool { return map[string]bool{h1: true} }}

	if err := c.srv.Pool(ec2meta.PoolRequest{Node: gw, IPs: []string{"10.0.0.1"}}); err == nil {
		t.Fatal("a private address went in the pool")
	}
	if err := c.srv.Pool(ec2meta.PoolRequest{Node: "n-nobody", IPs: []string{"203.0.113.10"}}); err == nil {
		t.Fatal("pool address on an unknown PC")
	}
	if err := c.srv.Pool(ec2meta.PoolRequest{Node: gw, IPs: []string{"203.0.113.10"}}); err != nil {
		t.Fatal(err)
	}
	a, err := c.srv.AllocateAddress(ec2meta.AddressRequest{Tenant: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicIP != "203.0.113.10" {
		t.Fatalf("allocated %+v", a)
	}
	_, err = c.srv.AllocateAddress(ec2meta.AddressRequest{Tenant: "alice"})
	wantCode(t, err, ec2meta.CodeAddressLimit)
	if err := c.srv.Pool(ec2meta.PoolRequest{IPs: []string{"203.0.113.10"}, Remove: true}); err == nil {
		t.Fatal("removed an allocated address from the pool")
	}

	r, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 2, Template: ec2meta.Instance{ImageID: ami, Type: "t3.micro"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	i1, i2 := r.Instances[0], r.Instances[1]
	as, err := c.srv.AssociateAddress(ec2meta.AddressRequest{Tenant: "alice", AllocationIDs: []string{a.AllocationID}, Instance: i1.ID})
	if err != nil {
		t.Fatal(err)
	}
	if as.AssociationID == "" || as.PrivateIP != i1.PrivateIP {
		t.Fatalf("associated %+v", as)
	}
	get := func(id string) ec2meta.Instance {
		t.Helper()
		got, err := c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}})
		if err != nil {
			t.Fatal(err)
		}
		return got[0]
	}
	if got := get(i1.ID); got.PublicIP != "203.0.113.10" {
		t.Fatalf("instance's public IP %q", got.PublicIP)
	}
	// The gateway PC joins the VPC, and every PC of it learns the address.
	for _, node := range []string{gw, h1} {
		v := c.srv.HostView(node)
		if len(v.Networks) != 1 || len(v.Networks[0].EIPs) != 1 {
			t.Fatalf("%s's view: %+v", node, v.Networks)
		}
		e := v.Networks[0].EIPs[0]
		if e.PublicIP != "203.0.113.10" || e.PrivateIP != i1.PrivateIP || e.Gateway != gw || e.GatewayIP == "" {
			t.Fatalf("elastic IP %+v", e)
		}
	}

	// Moving it needs the reassociation flag.
	_, err = c.srv.AssociateAddress(ec2meta.AddressRequest{Tenant: "alice", PublicIPs: []string{"203.0.113.10"}, Instance: i2.ID})
	wantCode(t, err, ec2meta.CodeAlreadyAssociated)
	if _, err := c.srv.AssociateAddress(ec2meta.AddressRequest{Tenant: "alice", PublicIPs: []string{"203.0.113.10"}, Instance: i2.ID, Reassociate: true}); err != nil {
		t.Fatal(err)
	}
	if get(i1.ID).PublicIP != "" || get(i2.ID).PublicIP != "203.0.113.10" {
		t.Fatal("not moved")
	}
	// Another tenant sees nothing of it.
	if _, err := c.srv.CreateTenant("bob"); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.ReleaseAddress(ec2meta.AddressRequest{Tenant: "bob", AllocationIDs: []string{a.AllocationID}}); err == nil {
		t.Fatal("bob released alice's address")
	}
	if err := c.srv.ReleaseAddress(ec2meta.AddressRequest{Tenant: "alice", AllocationIDs: []string{a.AllocationID}}); err == nil {
		t.Fatal("released an associated address")
	}
	// Terminating the instance frees the address.
	if _, err := c.srv.InstanceAction("alice", "terminate", []string{i2.ID}); err != nil {
		t.Fatal(err)
	}
	list, err := c.srv.Addresses(ec2meta.AddressRequest{Tenant: "alice"})
	if err != nil || len(list) != 1 || list[0].Instance != "" {
		t.Fatalf("after terminating: %+v, %v", list, err)
	}
	if v := c.srv.HostView(gw); len(v.Networks) != 0 {
		t.Fatalf("gateway still in the VPC: %+v", v.Networks)
	}
	if err := c.srv.ReleaseAddress(ec2meta.AddressRequest{Tenant: "alice", PublicIPs: []string{"203.0.113.10"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.Pool(ec2meta.PoolRequest{IPs: []string{"203.0.113.10"}, Remove: true}); err != nil {
		t.Fatal(err)
	}
	if p := c.srv.PublicIPs(); len(p) != 0 {
		t.Fatalf("pool %+v", p)
	}
}
