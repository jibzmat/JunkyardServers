package control

import (
	"net/http"
	"net/netip"
	"sort"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/pki"
)

// Elastic IPs (M5). The cluster's owner lists the public addresses PCs can
// take traffic for (jyctl public-ip add): extra addresses a provider
// routes to a PC, or spare ones on its LAN. Tenants allocate addresses
// from that pool and associate them with instances. The PC holding an
// address is the gateway for it: it joins the instance's VPC and passes
// traffic between the address and the instance, wherever the instance
// runs (vnet/eip.go).

const (
	opAllocateAddress     = "allocate_address"
	opReleaseAddress      = "release_address"
	opAssociateAddress    = "associate_address"
	opDisassociateAddress = "disassociate_address"
	opPool                = "address_pool"
)

func (f *fsm) applyAddress(c command) (any, bool, error) {
	e := &f.st.EC2
	x := c.EC2
	a := x.Address
	switch c.Op {
	case opPool:
		p := x.Pool
		if !p.Remove {
			if _, ok := f.st.Members[p.Node]; !ok {
				return nil, true, errCode(ec2meta.CodeInvalidParameter, "no PC %q", p.Node)
			}
		}
		for _, ip := range p.IPs {
			if p.Remove {
				if _, ok := e.PublicIPs[ip]; !ok {
					return nil, true, errCode(ec2meta.CodeAddressNotFound, "%s is not in the pool", ip)
				}
				if ad := addressByIP(e, ip); ad != nil {
					return nil, true, errCode(ec2meta.CodeAddressInUse, "%s is allocated (%s)", ip, ad.AllocationID)
				}
			} else if old, ok := e.PublicIPs[ip]; ok && old.Node != p.Node && addressByIP(e, ip) != nil {
				return nil, true, errCode(ec2meta.CodeAddressInUse, "%s is allocated; release it before moving it to another PC", ip)
			}
		}
		for _, ip := range p.IPs {
			if p.Remove {
				delete(e.PublicIPs, ip)
			} else {
				e.PublicIPs[ip] = &ec2meta.PublicIP{IP: ip, Node: p.Node}
			}
		}
		return nil, true, nil

	case opAllocateAddress:
		ip := a.PublicIP
		if ip != "" {
			if _, ok := e.PublicIPs[ip]; !ok || addressByIP(e, ip) != nil {
				return nil, true, errCode(ec2meta.CodeAddressLimit, "the address %s is not available", ip)
			}
		} else {
			var free []string
			for p := range e.PublicIPs {
				if addressByIP(e, p) == nil {
					free = append(free, p)
				}
			}
			if len(free) == 0 {
				return nil, true, errCode(ec2meta.CodeAddressLimit, "no public addresses left (add some with jyctl public-ip add)")
			}
			sort.Slice(free, func(i, j int) bool { return addrLess(free[i], free[j]) })
			ip = free[0]
		}
		n := ec2meta.Address{AllocationID: a.AllocationID, PublicIP: ip, Tenant: c.Owner, Tags: a.Tags, Created: c.Now}
		e.Addresses[n.AllocationID] = &n
		return n, true, nil

	case opReleaseAddress:
		old, ok := e.Addresses[a.AllocationID]
		if !ok || old.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeAllocationNotFound, "the allocation ID '%s' does not exist", a.AllocationID)
		}
		if old.Instance != "" {
			return nil, true, errCode(ec2meta.CodeAddressInUse, "the address %s is associated with %s", old.PublicIP, old.Instance)
		}
		delete(e.Addresses, old.AllocationID)
		return nil, true, nil

	case opAssociateAddress:
		old, ok := e.Addresses[a.AllocationID]
		if !ok || old.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeAllocationNotFound, "the allocation ID '%s' does not exist", a.AllocationID)
		}
		in, ok := e.Instances[a.Instance]
		if !ok || in.Tenant != c.Owner || in.State == ec2meta.StateTerminated || in.State == ec2meta.StateShuttingDown {
			return nil, true, errCode(ec2meta.CodeInvalidInstanceID, "the instance ID '%s' does not exist", a.Instance)
		}
		if old.Instance != "" && old.Instance != in.ID && x.Action != "reassociate" {
			return nil, true, errCode(ec2meta.CodeAlreadyAssociated, "the address %s is already associated with %s", old.PublicIP, old.Instance)
		}
		// An instance has one public address: a new one replaces the old.
		for id, o := range e.Addresses {
			if o.Instance == in.ID && id != old.AllocationID {
				d := *o
				d.Instance, d.PrivateIP, d.AssociationID = "", "", ""
				e.Addresses[id] = &d
			}
		}
		n := *old
		n.Instance, n.PrivateIP, n.AssociationID = in.ID, in.PrivateIP, a.AssociationID
		e.Addresses[n.AllocationID] = &n
		return n, true, nil

	case opDisassociateAddress:
		for id, o := range e.Addresses {
			if o.AssociationID != "" && o.AssociationID == a.AssociationID && o.Tenant == c.Owner {
				d := *o
				d.Instance, d.PrivateIP, d.AssociationID = "", "", ""
				e.Addresses[id] = &d
				return nil, true, nil
			}
		}
		return nil, true, errCode(ec2meta.CodeAssocNotFound, "the association ID '%s' does not exist", a.AssociationID)
	}
	return nil, false, nil
}

// tidyAddresses keeps addresses and instances in step after any EC2
// change: an instance that is gone or terminating loses its address (as on
// EC2), and each instance shows the address associated with it.
func (f *fsm) tidyAddresses() {
	e := &f.st.EC2
	public := map[string]string{}
	for id, a := range e.Addresses {
		if a.Instance == "" {
			continue
		}
		in, ok := e.Instances[a.Instance]
		if !ok || in.State == ec2meta.StateTerminated || in.State == ec2meta.StateShuttingDown {
			d := *a
			d.Instance, d.PrivateIP, d.AssociationID = "", "", ""
			e.Addresses[id] = &d
			continue
		}
		public[a.Instance] = a.PublicIP
	}
	for id, in := range e.Instances {
		if in.PublicIP != public[id] {
			n := *in
			n.PublicIP = public[id]
			e.Instances[id] = &n
		}
	}
}

func addressByIP(e *ec2State, ip string) *ec2meta.Address {
	for _, a := range e.Addresses {
		if a.PublicIP == ip {
			return a
		}
	}
	return nil
}

func addrLess(a, b string) bool {
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil {
		return a < b
	}
	return x.Less(y)
}

// vpcEIPs lists the elastic IPs in use in a VPC, as PCs route them.
func vpcEIPs(st *state, vpc string) []ec2meta.ElasticIP {
	var out []ec2meta.ElasticIP
	for _, a := range st.EC2.Addresses {
		in, ok := st.EC2.Instances[a.Instance]
		if a.Instance == "" || !ok || in.VpcID != vpc {
			continue
		}
		p, ok := st.EC2.PublicIPs[a.PublicIP]
		if !ok {
			continue
		}
		gwIP := ""
		if m, ok := st.Members[p.Node]; ok {
			gwIP = m.MeshIP
		}
		out = append(out, ec2meta.ElasticIP{PublicIP: a.PublicIP, PrivateIP: a.PrivateIP, Instance: a.Instance, Gateway: p.Node, GatewayIP: gwIP})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicIP < out[j].PublicIP })
	return out
}

// gatewayVPCs are the VPCs a PC is the gateway of an address in.
func gatewayVPCs(st *state, host string) []string {
	var out []string
	for _, a := range st.EC2.Addresses {
		p, ok := st.EC2.PublicIPs[a.PublicIP]
		in, iok := st.EC2.Instances[a.Instance]
		if a.Instance != "" && ok && iok && p.Node == host {
			out = append(out, in.VpcID)
		}
	}
	return out
}

// --- Server methods ---

func (s *Server) addressApply(op, tenant string, a ec2meta.Address, action string) (*ec2meta.Address, error) {
	res, err := s.ec2Apply(op, tenant, ec2Command{Address: &a, Action: action})
	if err != nil {
		return nil, err
	}
	if out, ok := res.(ec2meta.Address); ok {
		return &out, nil
	}
	return nil, nil
}

// AllocateAddress gives a tenant a public address from the pool (the one
// named, or any free one).
func (s *Server) AllocateAddress(req ec2meta.AddressRequest) (*ec2meta.Address, error) {
	ids, err := newIDs("eipalloc-")
	if err != nil {
		return nil, err
	}
	a := ec2meta.Address{AllocationID: ids[0], PublicIP: first(req.PublicIPs), Tags: req.Tags}
	if a.PublicIP != "" {
		if _, err := netip.ParseAddr(a.PublicIP); err != nil {
			return nil, errCode(ec2meta.CodeInvalidParameter, "invalid address %q", a.PublicIP)
		}
	}
	return s.addressApply(opAllocateAddress, req.Tenant, a, "")
}

// resolveAllocation finds the allocation ID a request names, by ID or by
// public address.
func (s *Server) resolveAllocation(req ec2meta.AddressRequest) (string, error) {
	if id := first(req.AllocationIDs); id != "" {
		return id, nil
	}
	ip := first(req.PublicIPs)
	var id string
	s.fsm.view(func(st *state) {
		if a := addressByIP(&st.EC2, ip); a != nil && a.Tenant == req.Tenant {
			id = a.AllocationID
		}
	})
	if id == "" {
		return "", errCode(ec2meta.CodeAddressNotFound, "the address '%s' is not allocated to you", ip)
	}
	return id, nil
}

// ReleaseAddress returns an address to the pool.
func (s *Server) ReleaseAddress(req ec2meta.AddressRequest) error {
	id, err := s.resolveAllocation(req)
	if err != nil {
		return err
	}
	_, err = s.addressApply(opReleaseAddress, req.Tenant, ec2meta.Address{AllocationID: id}, "")
	return err
}

// AssociateAddress points an address at an instance.
func (s *Server) AssociateAddress(req ec2meta.AddressRequest) (*ec2meta.Address, error) {
	id, err := s.resolveAllocation(req)
	if err != nil {
		return nil, err
	}
	ids, err := newIDs("eipassoc-")
	if err != nil {
		return nil, err
	}
	action := ""
	if req.Reassociate {
		action = "reassociate"
	}
	return s.addressApply(opAssociateAddress, req.Tenant, ec2meta.Address{AllocationID: id, Instance: req.Instance, AssociationID: ids[0]}, action)
}

// DisassociateAddress detaches an address from its instance, by
// association ID or address.
func (s *Server) DisassociateAddress(req ec2meta.AddressRequest) error {
	assoc := req.AssociationID
	if assoc == "" {
		ip := first(req.PublicIPs)
		s.fsm.view(func(st *state) {
			if a := addressByIP(&st.EC2, ip); a != nil && a.Tenant == req.Tenant {
				assoc = a.AssociationID
			}
		})
		if assoc == "" {
			return errCode(ec2meta.CodeAssocNotFound, "the address '%s' is not associated", ip)
		}
	}
	_, err := s.addressApply(opDisassociateAddress, req.Tenant, ec2meta.Address{AssociationID: assoc}, "")
	return err
}

// Addresses lists a tenant's addresses: all, or by allocation ID or
// address.
func (s *Server) Addresses(req ec2meta.AddressRequest) ([]ec2meta.Address, error) {
	var out []ec2meta.Address
	var err error
	s.fsm.view(func(st *state) {
		want := map[string]bool{}
		for _, id := range req.AllocationIDs {
			a, ok := st.EC2.Addresses[id]
			if !ok || a.Tenant != req.Tenant {
				err = errCode(ec2meta.CodeAllocationNotFound, "the allocation ID '%s' does not exist", id)
				return
			}
			want[id] = true
		}
		for _, ip := range req.PublicIPs {
			a := addressByIP(&st.EC2, ip)
			if a == nil || a.Tenant != req.Tenant {
				err = errCode(ec2meta.CodeAddressNotFound, "the address '%s' is not allocated to you", ip)
				return
			}
			want[a.AllocationID] = true
		}
		for _, a := range st.EC2.Addresses {
			if a.Tenant == req.Tenant && (len(want) == 0 || want[a.AllocationID]) {
				out = append(out, *a)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return addrLess(out[i].PublicIP, out[j].PublicIP) })
	return out, err
}

// Pool adds addresses to, or removes them from, the pool (admin).
func (s *Server) Pool(req ec2meta.PoolRequest) error {
	if len(req.IPs) == 0 {
		return errCode(ec2meta.CodeInvalidParameter, "no addresses given")
	}
	for _, ip := range req.IPs {
		a, err := netip.ParseAddr(ip)
		if err != nil || !a.Is4() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
			return errCode(ec2meta.CodeInvalidParameter, "%q is not a public IPv4 address", ip)
		}
	}
	_, err := s.ec2Apply(opPool, "", ec2Command{Pool: &req})
	return err
}

// PublicIPs lists the pool and what each address is allocated to.
func (s *Server) PublicIPs() []PoolEntry {
	var out []PoolEntry
	s.fsm.view(func(st *state) {
		for _, p := range st.EC2.PublicIPs {
			e := PoolEntry{PublicIP: *p}
			if a := addressByIP(&st.EC2, p.IP); a != nil {
				e.Tenant, e.AllocationID, e.Instance = a.Tenant, a.AllocationID, a.Instance
			}
			out = append(out, e)
		}
	})
	sort.Slice(out, func(i, j int) bool { return addrLess(out[i].IP, out[j].IP) })
	return out
}

// PoolEntry is a pool address and its allocation, if any.
type PoolEntry struct {
	ec2meta.PublicIP
	Tenant       string `json:"tenant,omitempty"`
	AllocationID string `json:"allocation_id,omitempty"`
	Instance     string `json:"instance,omitempty"`
}

// --- HTTP ---

func (s *Server) addressRoutes(mux *http.ServeMux) {
	gw := func(h http.HandlerFunc) http.HandlerFunc { return s.requireGateway(s.leaderOnly(h)) }
	mux.HandleFunc("POST /v1/ec2/addresses/allocate", gw(jsonHandler(s.AllocateAddress)))
	mux.HandleFunc("POST /v1/ec2/addresses/release", gw(jsonHandler(func(r ec2meta.AddressRequest) (struct{}, error) {
		return struct{}{}, s.ReleaseAddress(r)
	})))
	mux.HandleFunc("POST /v1/ec2/addresses/associate", gw(jsonHandler(s.AssociateAddress)))
	mux.HandleFunc("POST /v1/ec2/addresses/disassociate", gw(jsonHandler(func(r ec2meta.AddressRequest) (struct{}, error) {
		return struct{}{}, s.DisassociateAddress(r)
	})))
	mux.HandleFunc("POST /v1/ec2/addresses/list", gw(jsonHandler(s.Addresses)))
	admin := func(h http.HandlerFunc) http.HandlerFunc { return s.requireKind(s.leaderOnly(h), pki.KindAdmin) }
	mux.HandleFunc("POST /v1/admin/public-ips", admin(jsonHandler(func(r ec2meta.PoolRequest) (struct{}, error) {
		return struct{}{}, s.Pool(r)
	})))
	mux.HandleFunc("GET /v1/admin/public-ips", admin(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.PublicIPs())
	}))
}
