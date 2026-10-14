package control

import (
	"net/http"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// Console output is kept in the leader's memory, not the Raft log: it
// changes constantly, EC2 only promises recent output, and hosts resend
// it every few minutes, so a new leader soon has it again.

type consoleEntry ec2meta.ConsoleOutput

// PutConsole records the console output a host sends for an instance it
// runs.
func (s *Server) PutConsole(host string, c ec2meta.ConsoleOutput) error {
	ok := false
	s.fsm.view(func(st *state) {
		in, found := st.EC2.Instances[c.InstanceID]
		ok = found && in.Host == host
	})
	if !ok {
		return errStale
	}
	if len(c.Output) > ec2meta.MaxConsole {
		c.Output = c.Output[len(c.Output)-ec2meta.MaxConsole:]
	}
	c.Timestamp = s.now()
	s.consoleMu.Lock()
	defer s.consoleMu.Unlock()
	if s.consoles == nil {
		s.consoles = map[string]consoleEntry{}
	}
	s.consoles[c.InstanceID] = consoleEntry(c)
	return nil
}

// Console returns an instance's latest console output, empty if none has
// arrived yet.
func (s *Server) Console(tenant, id string) (*ec2meta.ConsoleOutput, error) {
	ok := false
	s.fsm.view(func(st *state) {
		in, found := st.EC2.Instances[id]
		ok = found && in.Tenant == tenant
	})
	if !ok {
		return nil, errCode(ec2meta.CodeInvalidInstanceID, "the instance ID '%s' does not exist", id)
	}
	s.consoleMu.Lock()
	defer s.consoleMu.Unlock()
	c := ec2meta.ConsoleOutput(s.consoles[id])
	c.InstanceID = id
	if c.Timestamp.IsZero() {
		c.Timestamp = s.now()
	}
	return &c, nil
}

func (s *Server) dropConsoles(ids []string) {
	s.consoleMu.Lock()
	defer s.consoleMu.Unlock()
	for _, id := range ids {
		delete(s.consoles, id)
	}
}

func (s *Server) handleConsole(w http.ResponseWriter, r *http.Request) {
	var req ec2meta.InstancesRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.IDs) != 1 {
		httpError(w, http.StatusBadRequest, "one instance ID")
		return
	}
	c, err := s.Console(req.Tenant, req.IDs[0])
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, c)
}

func (s *Server) handleHostConsole(w http.ResponseWriter, r *http.Request) {
	var c ec2meta.ConsoleOutput
	if !decodeLimit(w, r, &c, 4*ec2meta.MaxConsole) { // base64 in JSON
		return
	}
	if err := s.PutConsole(certName(r), c); err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, struct{}{})
}
