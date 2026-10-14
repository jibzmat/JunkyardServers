package membership

import (
	"bytes"
	"testing"
	"time"
)

func start(t *testing.T, id string, key []byte) *Membership {
	t.Helper()
	m, err := Start(Config{
		NodeID:    id,
		BindAddr:  "127.0.0.1:0",
		SecretKey: key,
		Meta:      Meta{NodeID: id, WGEndpoint: "203.0.113.1:51820"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Leave(time.Second) })
	return m
}

func waitAlive(t *testing.T, m *Membership, n int) []Meta {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if alive := m.Alive(); len(alive) == n {
			return alive
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("alive = %d, want %d", len(m.Alive()), n)
	return nil
}

func TestGossipJoin(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	a := start(t, "n-a", key)
	b := start(t, "n-b", key)
	if _, err := b.Join([]string{a.Addr()}); err != nil {
		t.Fatal(err)
	}
	alive := waitAlive(t, a, 2)
	for _, m := range alive {
		if m.WGEndpoint != "203.0.113.1:51820" {
			t.Fatalf("meta not carried: %+v", m)
		}
	}
}

func TestWrongGossipKeyCannotJoin(t *testing.T) {
	a := start(t, "n-a", bytes.Repeat([]byte{1}, 32))
	b := start(t, "n-b", bytes.Repeat([]byte{2}, 32))
	if _, err := b.Join([]string{a.Addr()}); err == nil {
		t.Fatal("join with the wrong gossip key succeeded")
	}
	if n := len(a.Alive()); n != 1 {
		t.Fatalf("a sees %d members", n)
	}
}

func TestRejectsBadKey(t *testing.T) {
	if _, err := Start(Config{NodeID: "x", BindAddr: "127.0.0.1:0", SecretKey: []byte("short")}); err == nil {
		t.Fatal("short gossip key accepted")
	}
}

func TestSendToAndSetMeta(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	got := make(chan string, 1)
	a, err := Start(Config{
		NodeID: "n-a", BindAddr: "127.0.0.1:0", SecretKey: key,
		Meta:      Meta{NodeID: "n-a"},
		OnMessage: func(from string, p []byte) { got <- from + ":" + string(p) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Leave(time.Second) })
	b := start(t, "n-b", key)
	if _, err := b.Join([]string{a.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitAlive(t, b, 2)
	if err := b.SendTo("n-a", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if m != "n-b:hello" {
			t.Fatalf("got %q", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("message not delivered")
	}

	if err := a.SetMeta(Meta{NodeID: "n-a", WGEndpoint: "198.51.100.1:51820"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range b.Alive() {
			if m.NodeID == "n-a" && m.WGEndpoint == "198.51.100.1:51820" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("updated meta did not reach b")
}
