package control

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// MeshCIDR is the address space of the node mesh (CGNAT range, unlikely to
// clash with home LANs).
const MeshCIDR = "100.64.0.0/10"

// allocateIP returns the lowest free host address in prefix, skipping the
// network address and anything in used.
func allocateIP(prefix netip.Prefix, used map[string]bool) (netip.Addr, error) {
	base := prefix.Masked().Addr()
	if !base.Is4() {
		return netip.Addr{}, errors.New("ipam: only IPv4 mesh prefixes are supported")
	}
	b4 := base.As4()
	start := binary.BigEndian.Uint32(b4[:])
	size := uint32(1) << (32 - prefix.Bits())
	for off := uint32(1); off < size-1; off++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], start+off)
		a := netip.AddrFrom4(b)
		if !used[a.String()] {
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("ipam: mesh address space exhausted")
}
