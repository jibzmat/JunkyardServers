package nat

import (
	"sort"
	"time"
)

// Tuning for path selection.
const (
	// HandshakeFresh: a WireGuard session whose last handshake is newer than
	// this is working. WireGuard re-handshakes every 2 minutes while in use,
	// and persistent keepalive keeps the mesh in use.
	HandshakeFresh = 3 * time.Minute
	// DirectGrace is how long a direct path gets to come up before relaying.
	DirectGrace = 45 * time.Second
	// RetryDirect is how often a relayed peer gets another direct attempt,
	// since NAT mappings change and punching often succeeds later.
	RetryDirect = 5 * time.Minute
)

// Mode is how a peer is reached.
type Mode int

const (
	Direct Mode = iota
	Relayed
)

// Route is the plan for one peer.
type Route struct {
	NodeID string
	Mode   Mode
	Via    string // relay node ID when Mode is Relayed
}

type pathState struct {
	mode  Mode
	via   string
	since time.Time
}

// Planner decides, peer by peer, whether to go direct or through a relay.
// It is not safe for concurrent use.
type Planner struct {
	paths map[string]*pathState
}

// NewPlanner returns a Planner with every peer starting direct.
func NewPlanner() *Planner { return &Planner{paths: map[string]*pathState{}} }

// Plan returns a route for each peer.
//
// peers are the other nodes' IDs; relays are node IDs eligible to relay
// (owner-trusted, alive, publicly reachable); lastHandshake gives each
// peer's latest direct WireGuard handshake (zero if none).
func (p *Planner) Plan(peers, relays []string, lastHandshake map[string]time.Time, now time.Time) []Route {
	isRelay := map[string]bool{}
	for _, r := range relays {
		isRelay[r] = true
	}
	fresh := func(id string) bool {
		t, ok := lastHandshake[id]
		return ok && !t.IsZero() && now.Sub(t) < HandshakeFresh
	}
	// Prefer relays we have a working session with; stable order.
	sorted := append([]string(nil), relays...)
	sort.Slice(sorted, func(i, j int) bool {
		fi, fj := fresh(sorted[i]), fresh(sorted[j])
		if fi != fj {
			return fi
		}
		return sorted[i] < sorted[j]
	})
	pickRelay := func(exclude string) string {
		for _, r := range sorted {
			if r != exclude {
				return r
			}
		}
		return ""
	}

	seen := map[string]bool{}
	var out []Route
	for _, id := range peers {
		seen[id] = true
		st := p.paths[id]
		if st == nil {
			st = &pathState{mode: Direct, since: now}
			p.paths[id] = st
		}
		switch {
		case isRelay[id]:
			// Relays are publicly reachable; always talk to them directly.
			st.mode, st.via = Direct, ""
		case st.mode == Direct && fresh(id):
			// Working; keep it.
		case st.mode == Direct && now.Sub(st.since) >= DirectGrace:
			if r := pickRelay(id); r != "" {
				st.mode, st.via, st.since = Relayed, r, now
			}
		case st.mode == Relayed && (now.Sub(st.since) >= RetryDirect || !isRelay[st.via]):
			// Time for another direct attempt, or the relay went away.
			st.mode, st.via, st.since = Direct, "", now
		}
		out = append(out, Route{NodeID: id, Mode: st.mode, Via: st.via})
	}
	for id := range p.paths {
		if !seen[id] {
			delete(p.paths, id)
		}
	}
	return out
}
