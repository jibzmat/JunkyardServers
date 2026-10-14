package control

import (
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// Reputation. Repair audits storage nodes (repair/audit.go) and records
// the results here. Each node's score starts at 1 for the owner's PCs and
// 0.5 for strangers', rises a little with each audit passed and halves
// with each one failed. A node whose score falls below suspendBelow is
// suspended: it gets no new shards or instances, and repair moves its
// shards to other nodes. It is reinstated once passing audits bring the
// score back to reinstateAt (suspended nodes are still audited).

const (
	opAudits = "audits"

	suspendBelow = 0.2
	reinstateAt  = 0.4
	// auditGain is how much of the way to 1 a passed audit moves the score.
	auditGain = 0.1
)

// startScore is a node's score before its first audit.
func startScore(m *cluster.Member) float64 {
	if m.Tier == cluster.TierTrusted {
		return 1
	}
	return 0.5
}

// applyAudits updates the audited nodes' records.
func (f *fsm) applyAudits(c command) error {
	for _, r := range c.Audits {
		m, ok := f.st.Members[r.Node]
		if !ok {
			continue
		}
		n := *m
		a := &n.Audits
		if a.Passed == 0 && a.Failed == 0 && a.Score == 0 {
			a.Score = startScore(m)
		}
		if r.OK {
			a.Passed++
			a.Score += (1 - a.Score) * auditGain
		} else {
			a.Failed++
			a.Score /= 2
			a.LastFail = c.Now.UTC().Format(time.RFC3339)
		}
		switch {
		case !a.Suspended && a.Score < suspendBelow:
			a.Suspended = true
		case a.Suspended && a.Score >= reinstateAt:
			a.Suspended = false
		}
		f.st.Members[r.Node] = &n
	}
	return nil
}

// RecordAudits stores the results of storage audits (for repair).
func (s *Server) RecordAudits(results []storage.AuditResult) error {
	if len(results) == 0 {
		return nil
	}
	return s.apply(command{Op: opAudits, Now: s.now().UTC(), Audits: results})
}
