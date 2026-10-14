package control

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// Disk replicas and failover. Each instance with a host gets a second
// compute PC, its replica, which keeps a live copy of the root disk and
// attached volumes: the host mirrors every write there before the guest
// sees it complete. When the host has been gone a while and the copy is
// in step, the instance moves to the replica and boots from the copy, and
// a new replica is chosen.

const (
	opSetReplica    = "set_replica"
	opReplicaReport = "replica_report"
	opFailover      = "failover"
	opMoveVolume    = "move_volume"
)

// failoverReason is the state reason of an instance moved to its replica.
const failoverReason = "Server.HostFailure: its PC was lost; restarted on another PC from a copy of its disks"

func (f *fsm) applyReplica(c command) (any, bool, error) {
	e := &f.st.EC2
	x := c.EC2
	switch c.Op {
	case opSetReplica:
		in, ok := e.Instances[x.IDs[0]]
		if !ok || in.Host != x.Host || x.Target == in.Host || in.State == ec2meta.StateTerminated {
			return nil, true, errStale
		}
		if _, ok := f.st.Members[x.Target]; x.Target != "" && !ok {
			return nil, true, errStale
		}
		n := *in
		n.Replica, n.ReplicaSynced = x.Target, false
		e.Instances[n.ID] = &n
		for id, v := range e.Volumes {
			if v.Instance == n.ID {
				nv := *v
				nv.Replica, nv.ReplicaSynced = x.Target, false
				e.Volumes[id] = &nv
			}
		}
		return nil, true, nil

	case opReplicaReport:
		r := x.ReplicaReport
		in, ok := e.Instances[r.Instance]
		if !ok || in.Host != x.Host || in.Replica != r.Replica || in.Replica == "" {
			return nil, true, errStale
		}
		n := *in
		n.ReplicaSynced = r.Synced
		e.Instances[n.ID] = &n
		synced := map[string]bool{}
		for _, id := range r.Volumes {
			synced[id] = true
		}
		for id, v := range e.Volumes {
			if v.Instance == n.ID && v.Replica == n.Replica && v.ReplicaSynced != synced[id] {
				nv := *v
				nv.ReplicaSynced = synced[id]
				e.Volumes[id] = &nv
			}
		}
		return nil, true, nil

	case opFailover:
		in, ok := e.Instances[x.IDs[0]]
		if !ok || in.Host != x.Host || in.Replica == "" || !in.ReplicaSynced {
			return nil, true, errStale
		}
		if _, ok := f.st.Members[in.Replica]; !ok {
			return nil, true, errStale
		}
		n := *in
		switch n.State {
		case ec2meta.StateRunning, ec2meta.StatePending:
			n.State, n.Changed = ec2meta.StatePending, c.Now
		case ec2meta.StateStopping:
			n.State, n.Changed = ec2meta.StateStopped, c.Now
		case ec2meta.StateStopped:
		default:
			return nil, true, errStale
		}
		to := n.Replica
		n.Host, n.Replica, n.ReplicaSynced, n.Recovered = to, "", false, true
		n.StateReason = failoverReason
		e.Instances[n.ID] = &n
		for id, v := range e.Volumes {
			if v.Instance != n.ID {
				continue
			}
			nv := *v
			if (nv.Replica == to && nv.ReplicaSynced) || !nv.Ready {
				// The copy is in step, or there is no data yet.
				nv.Host, nv.Replica, nv.ReplicaSynced = to, "", false
				if nv.AttachState == ec2meta.AttachDetaching {
					nv.Instance, nv.Device, nv.AttachState, nv.AttachTime = "", "", "", time.Time{}
					nv.State = ec2meta.VolumeAvailable
				}
			} else {
				// Its data is only on the lost PC: leave it there, detached.
				nv.Instance, nv.Device, nv.AttachState, nv.AttachTime = "", "", "", time.Time{}
				nv.State = ec2meta.VolumeAvailable
			}
			e.Volumes[id] = &nv
		}
		return n, true, nil

	case opMoveVolume:
		v, ok := e.Volumes[x.IDs[0]]
		if !ok || v.Host != x.Host || v.Instance != "" || v.Replica == "" || !v.ReplicaSynced {
			return nil, true, errStale
		}
		nv := *v
		nv.Host, nv.Replica, nv.ReplicaSynced = v.Replica, "", false
		e.Volumes[nv.ID] = &nv
		return nil, true, nil
	}
	return nil, false, nil
}

// lostFor reports how long a node has been seen dead by this leader (zero
// while alive), from the gossip snapshot alive.
func (s *Server) lostFor(alive map[string]bool, id string, now time.Time) time.Duration {
	s.lostMu.Lock()
	defer s.lostMu.Unlock()
	if alive == nil || alive[id] {
		delete(s.lostSince, id)
		return 0
	}
	if s.lostSince == nil {
		s.lostSince = map[string]time.Time{}
	}
	t, ok := s.lostSince[id]
	if !ok {
		s.lostSince[id] = now
		return 0
	}
	return now.Sub(t)
}

// scheduleReplicas fails instances and volumes over from lost hosts and
// gives every placed instance a replica.
func (s *Server) scheduleReplicas(alive map[string]bool, now time.Time) error {
	opts := s.computeOpts()
	isAlive := func(id string) bool { return alive == nil || alive[id] }
	lost := map[string]bool{}
	type move struct{ id, host, target string }
	var failovers, volMoves, replicas []move
	s.fsm.view(func(st *state) {
		for id := range st.Members {
			if s.lostFor(alive, id, now) > hostLostAfter {
				lost[id] = true
			}
		}
		usedCPU, usedMem := map[string]int{}, map[string]int{}
		for _, in := range st.EC2.Instances {
			if usesHost(in) {
				usedCPU[in.Host] += in.VCPU
				usedMem[in.Host] += in.MemMiB
			}
		}
		ids := make([]string, 0, len(st.EC2.Instances))
		for id := range st.EC2.Instances {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			in := st.EC2.Instances[id]
			if in.Host == "" || in.State == ec2meta.StateTerminated || in.State == ec2meta.StateShuttingDown {
				continue
			}
			if lost[in.Host] {
				if in.Replica != "" && in.ReplicaSynced && isAlive(in.Replica) && !lost[in.Replica] {
					failovers = append(failovers, move{in.ID, in.Host, in.Replica})
					if usesHost(in) {
						usedCPU[in.Replica] += in.VCPU
						usedMem[in.Replica] += in.MemMiB
					}
				}
				continue
			}
			if in.Replica != "" && !lost[in.Replica] {
				if m, ok := st.Members[in.Replica]; ok && s.eligible(m, *in, opts.AllowEmulation) {
					continue
				}
			}
			// Pick the least-loaded other host that could take it over.
			best, bestLoad := "", 2.0
			for mid, m := range st.Members {
				if mid == in.Host || !isAlive(mid) || !s.eligible(m, *in, opts.AllowEmulation) {
					continue
				}
				cpu, mem := capacity(m)
				if usedCPU[mid]+in.VCPU > cpu || usedMem[mid]+in.MemMiB > mem {
					continue
				}
				load := float64(usedMem[mid]+in.MemMiB) / float64(mem)
				if load < bestLoad || (load == bestLoad && mid < best) {
					best, bestLoad = mid, load
				}
			}
			if best != in.Replica {
				replicas = append(replicas, move{in.ID, in.Host, best})
			}
		}
		for _, v := range st.EC2.Volumes {
			if v.Instance == "" && v.Host != "" && lost[v.Host] && v.Replica != "" && v.ReplicaSynced && isAlive(v.Replica) && !lost[v.Replica] {
				volMoves = append(volMoves, move{v.ID, v.Host, v.Replica})
			}
		}
	})
	var errs []error
	for _, m := range failovers {
		if _, err := s.ec2Apply(opFailover, "", ec2Command{IDs: []string{m.id}, Host: m.host}); err != nil && !errors.Is(err, errStale) {
			errs = append(errs, err)
		}
	}
	for _, m := range volMoves {
		if _, err := s.ec2Apply(opMoveVolume, "", ec2Command{IDs: []string{m.id}, Host: m.host}); err != nil && !errors.Is(err, errStale) {
			errs = append(errs, err)
		}
	}
	for _, m := range replicas {
		if _, err := s.ec2Apply(opSetReplica, "", ec2Command{IDs: []string{m.id}, Host: m.host, Target: m.target}); err != nil && !errors.Is(err, errStale) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// replicaDisks lists the disks host keeps copies of.
func replicaDisks(st *state, host string) []ec2meta.ReplicaDisk {
	var out []ec2meta.ReplicaDisk
	for _, in := range st.EC2.Instances {
		if in.Replica == host && in.Host != "" && in.State != ec2meta.StateTerminated {
			out = append(out, ec2meta.ReplicaDisk{ID: in.ID, Primary: in.Host})
		}
	}
	for _, v := range st.EC2.Volumes {
		if v.Replica == host && v.Host != "" && v.State != ec2meta.VolumeDeleted {
			out = append(out, ec2meta.ReplicaDisk{ID: v.ID, Primary: v.Host})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ReportReplica records how far an instance's disk copies are.
func (s *Server) ReportReplica(host string, r ec2meta.ReplicaReport) error {
	_, err := s.ec2Apply(opReplicaReport, "", ec2Command{Host: host, ReplicaReport: &r})
	return err
}

func (s *Server) handleReplicaReport(w http.ResponseWriter, r *http.Request) {
	var rep ec2meta.ReplicaReport
	if !decode(w, r, &rep) {
		return
	}
	if err := s.ReportReplica(certName(r), rep); err != nil {
		if errors.Is(err, errStale) {
			httpError(w, http.StatusConflict, err.Error())
			return
		}
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}
