package nat

import (
	"net/netip"
	"testing"
	"time"
)

func TestReflectorMajority(t *testing.T) {
	r := NewReflector()
	now := time.Now()
	r.Observe("a", "203.0.113.7:51820", now)
	r.Observe("b", "203.0.113.7:51820", now)
	r.Observe("liar", "198.51.100.9:1234", now)
	ep, ok := r.Endpoint(now, nil)
	if !ok || ep != "203.0.113.7:51820" {
		t.Fatalf("got %q %v", ep, ok)
	}
}

func TestReflectorTrustedWinsTies(t *testing.T) {
	r := NewReflector()
	now := time.Now()
	r.Observe("stranger", "198.51.100.9:1234", now)
	r.Observe("mine", "203.0.113.7:51820", now)
	ep, _ := r.Endpoint(now, func(id string) bool { return id == "mine" })
	if ep != "203.0.113.7:51820" {
		t.Fatalf("got %q", ep)
	}
}

func TestReflectorIgnoresPrivateAndExpires(t *testing.T) {
	r := NewReflector()
	now := time.Now()
	for _, ep := range []string{"192.168.1.5:51820", "127.0.0.1:1", "100.64.0.3:51820", "10.0.0.1:5", "garbage", "203.0.113.1:0"} {
		if r.Observe("x", ep, now) {
			t.Errorf("accepted %q", ep)
		}
	}
	r.Observe("a", "203.0.113.7:51820", now)
	if _, ok := r.Endpoint(now.Add(ObservationTTL+time.Second), nil); ok {
		t.Fatal("expired observation still counted")
	}
}

func TestIsPublic(t *testing.T) {
	if !IsPublic(netip.MustParseAddr("8.8.8.8")) || IsPublic(netip.MustParseAddr("172.16.0.1")) {
		t.Fatal("IsPublic wrong")
	}
}

func TestPlannerFallsBackToRelayAndRetries(t *testing.T) {
	p := NewPlanner()
	t0 := time.Now()
	peers := []string{"natted", "relay"}
	relays := []string{"relay"}
	hs := map[string]time.Time{"relay": t0}

	r := p.Plan(peers, relays, hs, t0)
	if r[0].Mode != Direct || r[1].Mode != Direct {
		t.Fatalf("start: %+v", r)
	}
	// No handshake with "natted" after the grace period: relay through "relay".
	r = p.Plan(peers, relays, hs, t0.Add(DirectGrace))
	if r[0].Mode != Relayed || r[0].Via != "relay" {
		t.Fatalf("after grace: %+v", r[0])
	}
	if r[1].Mode != Direct {
		t.Fatal("relay itself must stay direct")
	}
	// Later, try direct again.
	r = p.Plan(peers, relays, hs, t0.Add(DirectGrace+RetryDirect))
	if r[0].Mode != Direct {
		t.Fatalf("retry: %+v", r[0])
	}
}

func TestPlannerKeepsWorkingDirectPath(t *testing.T) {
	p := NewPlanner()
	t0 := time.Now()
	later := t0.Add(2 * DirectGrace)
	r := p.Plan([]string{"b"}, []string{"relay"}, map[string]time.Time{"b": later.Add(-time.Second)}, t0)
	r = p.Plan([]string{"b"}, []string{"relay"}, map[string]time.Time{"b": later.Add(-time.Second)}, later)
	if r[0].Mode != Direct {
		t.Fatalf("working direct path abandoned: %+v", r[0])
	}
}

func TestPlannerNoRelayStaysDirect(t *testing.T) {
	p := NewPlanner()
	t0 := time.Now()
	p.Plan([]string{"b"}, nil, nil, t0)
	r := p.Plan([]string{"b"}, nil, nil, t0.Add(time.Hour))
	if r[0].Mode != Direct {
		t.Fatalf("relayed with no relay: %+v", r[0])
	}
}

func TestPlannerRelayGoneReturnsDirect(t *testing.T) {
	p := NewPlanner()
	t0 := time.Now()
	p.Plan([]string{"b", "r"}, []string{"r"}, nil, t0)
	r := p.Plan([]string{"b", "r"}, []string{"r"}, nil, t0.Add(DirectGrace))
	if r[0].Mode != Relayed {
		t.Fatalf("want relayed: %+v", r[0])
	}
	r = p.Plan([]string{"b"}, nil, nil, t0.Add(DirectGrace+time.Second))
	if r[0].Mode != Direct {
		t.Fatalf("relay gone but still relayed: %+v", r[0])
	}
}
