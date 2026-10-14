package control

import (
	"errors"
	"net/http"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// Live migration. An instance migrates to its replica, which already holds
// an up-to-date copy of its disks: the owner asks for it (jyctl migrate),
// or drains its host (jyctl drain). The source host streams the VM's
// memory to the replica's jyd (see compute/migrate.go) and reports the
// result here, which moves the instance.

const (
	opMigrate  = "migrate"
	opMigrated = "migrated"
	opDrain    = "drain"
)

func (f *fsm) applyMigration(c command) (any, bool, error) {
	e := &f.st.EC2
	x := c.EC2
	switch c.Op {
	case opMigrate:
		in, ok := e.Instances[x.IDs[0]]
		if !ok || in.Host == "" || in.Host != x.Host {
			return nil, true, errStale
		}
		if in.State != ec2meta.StateRunning {
			return nil, true, errCode(ec2meta.CodeIncorrectState, "instance %s is %s; only running instances migrate", in.ID, in.State)
		}
		if _, ok := f.st.Members[x.Target]; !ok || x.Target == in.Host {
			return nil, true, errCode(ec2meta.CodeInvalidParameter, "no PC %q to migrate %s to", x.Target, in.ID)
		}
		n := *in
		if n.Replica != x.Target {
			// The disks must be copied there first; the host migrates
			// once the copy is in step.
			n.Replica, n.ReplicaSynced = x.Target, false
			for id, v := range e.Volumes {
				if v.Instance == n.ID {
					nv := *v
					nv.Replica, nv.ReplicaSynced = x.Target, false
					e.Volumes[id] = &nv
				}
			}
		}
		n.MigrateTo = x.Target
		e.Instances[n.ID] = &n
		return n, true, nil

	case opMigrated:
		r := x.Migration
		in, ok := e.Instances[r.Instance]
		if !ok || in.Host != x.Host || in.MigrateTo != r.To {
			return nil, true, errStale
		}
		n := *in
		n.MigrateTo = ""
		if r.OK {
			n.Host, n.Replica, n.ReplicaSynced = r.To, "", false
			for id, v := range e.Volumes {
				if v.Instance == n.ID {
					nv := *v
					nv.Host, nv.Replica, nv.ReplicaSynced = r.To, "", false
					e.Volumes[id] = &nv
				}
			}
		}
		e.Instances[n.ID] = &n
		return nil, true, nil

	case opDrain:
		m, ok := f.st.Members[x.Target]
		if !ok {
			return nil, true, errCode(ec2meta.CodeInvalidParameter, "no PC %q", x.Target)
		}
		n := *m
		n.Drained = x.Action == "drain"
		f.st.Members[n.NodeID] = &n
		return nil, true, nil
	}
	return nil, false, nil
}

// Migrate live-migrates an instance, or drains or undrains a node.
func (s *Server) Migrate(req ec2meta.MigrateRequest) (*ec2meta.Instance, error) {
	switch {
	case req.Drain != "":
		_, err := s.ec2Apply(opDrain, "", ec2Command{Target: req.Drain, Action: "drain"})
		s.kickScheduler()
		return nil, err
	case req.Undrain != "":
		_, err := s.ec2Apply(opDrain, "", ec2Command{Target: req.Undrain, Action: "undrain"})
		return nil, err
	}
	var in ec2meta.Instance
	found := false
	s.fsm.view(func(st *state) {
		if x, ok := st.EC2.Instances[req.Instance]; ok {
			in, found = *x, true
		}
	})
	if !found {
		return nil, errCode(ec2meta.CodeInvalidInstanceID, "the instance ID '%s' does not exist", req.Instance)
	}
	to := req.To
	if to == "" {
		to = in.Replica
	}
	if to == "" {
		return nil, errCode(ec2meta.CodeIncorrectState, "instance %s has no replica PC yet; name one with -to", in.ID)
	}
	res, err := s.ec2Apply(opMigrate, "", ec2Command{IDs: []string{in.ID}, Host: in.Host, Target: to})
	if err != nil {
		return nil, err
	}
	out := res.(ec2meta.Instance)
	return &out, nil
}

// ReportMigration records how a live migration ended.
func (s *Server) ReportMigration(host string, r ec2meta.MigrationReport) error {
	_, err := s.ec2Apply(opMigrated, "", ec2Command{Host: host, Migration: &r})
	return err
}

func (s *Server) handleMigrate(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.MigrateRequest
	if !decode(w, r, &req) {
		return
	}
	in, err := s.Migrate(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, in)
}

func (s *Server) handleMigrated(w http.ResponseWriter, r *http.Request) {
	var rep ec2meta.MigrationReport
	if !decode(w, r, &rep) {
		return
	}
	if err := s.ReportMigration(certName(r), rep); err != nil {
		if errors.Is(err, errStale) {
			httpError(w, http.StatusConflict, err.Error())
			return
		}
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}
