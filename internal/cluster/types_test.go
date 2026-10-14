package cluster

import "testing"

func TestParseRoles(t *testing.T) {
	rs, err := ParseRoles("storage, compute,storage")
	if err != nil || len(rs) != 2 {
		t.Fatalf("got %v %v", rs, err)
	}
	if _, err := ParseRoles("storage,miner"); err == nil {
		t.Fatal("unknown role accepted")
	}
}

func TestTierRoles(t *testing.T) {
	all := []Role{RoleControl, RoleGateway, RoleCompute, RoleStorage}
	for _, tier := range []Tier{TierUntrusted, TierConfidential} {
		got := tier.AllowedRoles(all)
		if len(got) != 2 || got[0] != RoleCompute || got[1] != RoleStorage {
			t.Fatalf("%s allowed %v, want compute and storage", tier, got)
		}
	}
	if got := TierTrusted.AllowedRoles(all); len(got) != 4 {
		t.Fatalf("trusted allowed %v", got)
	}
}

func TestPlacement(t *testing.T) {
	cases := []struct {
		p            Placement
		tier         Tier
		confidential bool
		want         bool
	}{
		{PlacementAny, TierUntrusted, false, true},
		{PlacementPrivate, TierUntrusted, false, false},
		{PlacementPrivate, TierTrusted, false, true},
		{PlacementPrivate, TierConfidential, true, true},
		{PlacementConfidential, TierTrusted, false, false},
		{PlacementConfidential, TierConfidential, true, true},
		{PlacementConfidential, TierTrusted, true, true},
	}
	for _, c := range cases {
		if got := c.p.Allows(c.tier, c.confidential); got != c.want {
			t.Errorf("%s on %s (confidential=%v) = %v, want %v", c.p, c.tier, c.confidential, got, c.want)
		}
	}
	if p, err := ParsePlacement(""); err != nil || p != PlacementPrivate {
		t.Fatalf("default placement %v %v", p, err)
	}
	if _, err := ParsePlacement("cheap"); err == nil {
		t.Fatal("unknown placement accepted")
	}
}
