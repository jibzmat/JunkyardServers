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
	if got := TierStorageOnly.AllowedRoles(all); len(got) != 1 || got[0] != RoleStorage {
		t.Fatalf("storage-only allowed %v", got)
	}
	if got := TierTrusted.AllowedRoles(all); len(got) != 4 {
		t.Fatalf("trusted allowed %v", got)
	}
}
