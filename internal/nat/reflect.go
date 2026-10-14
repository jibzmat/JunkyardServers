// Package nat gets nodes behind home routers talking to each other.
//
// Endpoint reflection: a node can't see its own public address from behind
// NAT, but its peers can. Every node that has a live WireGuard session with a
// peer tells that peer which address its packets arrive from. The peer takes
// the address most observers agree on and advertises it in gossip, so other
// nodes behind NAT can punch through to it.
//
// Relays: when two nodes can't complete a direct handshake (both behind
// strict NATs), each routes the other's mesh address through an owner-trusted
// node with a public endpoint.
package nat

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// ObservationTTL is how long a peer's report of our endpoint counts.
const ObservationTTL = 10 * time.Minute

type observation struct {
	endpoint string
	at       time.Time
}

// Reflector collects what peers report as this node's public endpoint.
type Reflector struct {
	mu  sync.Mutex
	obs map[string]observation // observer node ID -> what it saw
}

// NewReflector returns an empty Reflector.
func NewReflector() *Reflector {
	return &Reflector{obs: map[string]observation{}}
}

// Observe records that observer sees this node at endpoint. Endpoints that
// are not a public IP:port are ignored: a LAN or loopback address is useless
// to peers elsewhere and is often what a liar would send.
func (r *Reflector) Observe(observer, endpoint string, now time.Time) bool {
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil || ap.Port() == 0 || !IsPublic(ap.Addr()) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs[observer] = observation{endpoint: ap.String(), at: now}
	return true
}

// Endpoint returns the endpoint reported by the most distinct observers in
// the last ObservationTTL. trusted breaks ties in favour of addresses vouched
// for by owner-trusted observers, then the lexically smallest address so the
// answer is stable.
func (r *Reflector) Endpoint(now time.Time, trusted func(observer string) bool) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	type tally struct{ total, trusted int }
	votes := map[string]*tally{}
	for id, o := range r.obs {
		if now.Sub(o.at) > ObservationTTL {
			delete(r.obs, id)
			continue
		}
		t := votes[o.endpoint]
		if t == nil {
			t = &tally{}
			votes[o.endpoint] = t
		}
		t.total++
		if trusted != nil && trusted(id) {
			t.trusted++
		}
	}
	if len(votes) == 0 {
		return "", false
	}
	eps := make([]string, 0, len(votes))
	for ep := range votes {
		eps = append(eps, ep)
	}
	sort.Slice(eps, func(i, j int) bool {
		a, b := votes[eps[i]], votes[eps[j]]
		if a.trusted != b.trusted {
			return a.trusted > b.trusted
		}
		if a.total != b.total {
			return a.total > b.total
		}
		return eps[i] < eps[j]
	})
	return eps[0], true
}

// IsPublic reports whether addr is routable on the internet.
func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	// 100.64.0.0/10 is carrier-grade NAT, and also the mesh's own range.
	if netip.MustParsePrefix("100.64.0.0/10").Contains(addr) {
		return false
	}
	return true
}
