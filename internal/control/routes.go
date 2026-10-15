package control

import (
	"net/http"
	"sort"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// Route tables and NAT gateways (M5). Every VPC has a main route table
// (ec2meta.MainRouteTable) and an internet gateway (ec2meta.InternetGateway)
// that exist without being created; the main table is stored only once it
// changes. A route table holds at most the default route, to the internet
// gateway (out through each instance's own PC, as before), or to a NAT
// gateway (out through the PC holding its elastic IP). A subnet whose
// table has neither has no internet. vpcNet hands PCs the result as
// VPCNet.Egress.

const (
	opCreateRouteTable = "create_route_table"
	opDeleteRouteTable = "delete_route_table"
	opRoute            = "route"
	opAssociateRT      = "associate_route_table"
	opDisassociateRT   = "disassociate_route_table"
	opCreateNat        = "create_nat_gateway"
	opDeleteNat        = "delete_nat_gateway"

	// deletedNatLinger is how long a deleted NAT gateway is still listed.
	deletedNatLinger = time.Hour
)

// routeCommand carries route table and NAT gateway operations.
type routeCommand struct {
	Req   ec2meta.RouteRequest `json:"req"`
	NewID string               `json:"new_id,omitempty"` // the table, association or gateway made
}

// mainTable is a VPC's main route table as it stands.
func mainTable(e *ec2State, vpc *ec2meta.VPC) *ec2meta.RouteTable {
	id := ec2meta.MainRouteTable(vpc.ID)
	if t, ok := e.RouteTables[id]; ok {
		return t
	}
	return &ec2meta.RouteTable{ID: id, Tenant: vpc.Tenant, VpcID: vpc.ID, Main: true, Created: vpc.Created,
		Routes: []ec2meta.Route{{Destination: ec2meta.DefaultRoute, Gateway: ec2meta.InternetGateway(vpc.ID)}}}
}

// routeTable finds a tenant's table, main ones included.
func routeTable(e *ec2State, tenant, id string) (*ec2meta.RouteTable, error) {
	if t, ok := e.RouteTables[id]; ok && t.Tenant == tenant {
		return t, nil
	}
	for _, v := range e.VPCs {
		if v.Tenant == tenant && ec2meta.MainRouteTable(v.ID) == id {
			return mainTable(e, v), nil
		}
	}
	return nil, errCode(ec2meta.CodeRouteTableNotFound, "the route table ID '%s' does not exist", id)
}

// subnetTable is the table a subnet uses.
func subnetTable(e *ec2State, sn *ec2meta.Subnet) *ec2meta.RouteTable {
	for _, t := range e.RouteTables {
		if t.VpcID != sn.VpcID {
			continue
		}
		for _, a := range t.Associations {
			if a.Subnet == sn.ID {
				return t
			}
		}
	}
	if v, ok := e.VPCs[sn.VpcID]; ok {
		return mainTable(e, v)
	}
	return nil
}

func defaultRoute(t *ec2meta.RouteTable) *ec2meta.Route {
	for i := range t.Routes {
		if t.Routes[i].Destination == ec2meta.DefaultRoute {
			return &t.Routes[i]
		}
	}
	return nil
}

func copyTable(t *ec2meta.RouteTable) ec2meta.RouteTable {
	n := *t
	n.Routes = append([]ec2meta.Route(nil), t.Routes...)
	n.Associations = append([]ec2meta.RouteTableAssoc(nil), t.Associations...)
	return n
}

func (f *fsm) applyRoutes(c command) (any, bool, error) {
	e := &f.st.EC2
	if c.EC2.Routes == nil {
		return nil, false, nil
	}
	rc := c.EC2.Routes
	r := rc.Req
	switch c.Op {
	case opCreateRouteTable:
		vpc, ok := e.VPCs[r.VpcID]
		if !ok || vpc.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeVpcNotFound, "the vpc ID '%s' does not exist", r.VpcID)
		}
		t := ec2meta.RouteTable{ID: rc.NewID, Tenant: c.Owner, VpcID: vpc.ID, Created: c.Now, Tags: r.Tags}
		e.RouteTables[t.ID] = &t
		return t, true, nil

	case opDeleteRouteTable:
		t, err := routeTable(e, c.Owner, r.TableID)
		if err != nil {
			return nil, true, err
		}
		if t.Main {
			return nil, true, errCode(ec2meta.CodeDependency, "the main route table of %s can't be deleted", t.VpcID)
		}
		if len(t.Associations) > 0 {
			return nil, true, errCode(ec2meta.CodeDependency, "the route table '%s' has dependencies (subnet %s) and cannot be deleted", t.ID, t.Associations[0].Subnet)
		}
		delete(e.RouteTables, t.ID)
		return nil, true, nil

	case opRoute:
		t, err := routeTable(e, c.Owner, r.TableID)
		if err != nil {
			return nil, true, err
		}
		n := copyTable(t)
		cur := defaultRoute(&n)
		switch c.EC2.Action {
		case "delete":
			if cur == nil {
				return nil, true, errCode(ec2meta.CodeRouteNotFound, "no route to %s in %s", ec2meta.DefaultRoute, t.ID)
			}
			n.Routes = nil
		default:
			want := *r.Route
			switch {
			case want.NatGateway != "":
				g, ok := e.NatGateways[want.NatGateway]
				if !ok || g.Tenant != c.Owner || g.State != ec2meta.NatAvailable {
					return nil, true, errCode(ec2meta.CodeNatNotFound, "the NAT gateway '%s' does not exist", want.NatGateway)
				}
				if g.VpcID != t.VpcID {
					return nil, true, errCode(ec2meta.CodeInvalidParameter, "the NAT gateway %s is in another VPC", g.ID)
				}
			case want.Gateway != ec2meta.InternetGateway(t.VpcID):
				return nil, true, errCode(ec2meta.CodeGatewayNotFound, "the gateway '%s' is not this VPC's internet gateway (%s)", want.Gateway, ec2meta.InternetGateway(t.VpcID))
			}
			if cur != nil && !r.Replace {
				return nil, true, errCode(ec2meta.CodeRouteExists, "the route %s already exists in %s", ec2meta.DefaultRoute, t.ID)
			}
			if cur == nil && r.Replace {
				return nil, true, errCode(ec2meta.CodeRouteNotFound, "no route to %s in %s", ec2meta.DefaultRoute, t.ID)
			}
			n.Routes = []ec2meta.Route{want}
		}
		e.RouteTables[n.ID] = &n
		return nil, true, nil

	case opAssociateRT:
		t, err := routeTable(e, c.Owner, r.TableID)
		if err != nil {
			return nil, true, err
		}
		sn, ok := e.Subnets[r.SubnetID]
		if !ok || sn.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeSubnetNotFound, "the subnet ID '%s' does not exist", r.SubnetID)
		}
		if sn.VpcID != t.VpcID {
			return nil, true, errCode(ec2meta.CodeInvalidParameter, "the subnet %s is in another VPC than %s", sn.ID, t.ID)
		}
		if t.Main {
			return nil, true, errCode(ec2meta.CodeInvalidParameter, "subnets use the main table unless given another; associate %s with a table you created", sn.ID)
		}
		if cur := subnetTable(e, sn); cur != nil && !cur.Main {
			return nil, true, errCode("Resource.AlreadyAssociated", "the subnet %s is already associated with %s", sn.ID, cur.ID)
		}
		n := copyTable(t)
		n.Associations = append(n.Associations, ec2meta.RouteTableAssoc{ID: rc.NewID, Subnet: sn.ID})
		e.RouteTables[n.ID] = &n
		return rc.NewID, true, nil

	case opDisassociateRT:
		for id, t := range e.RouteTables {
			if t.Tenant != c.Owner {
				continue
			}
			for i, a := range t.Associations {
				if a.ID == r.AssociationID {
					n := copyTable(t)
					n.Associations = append(n.Associations[:i:i], n.Associations[i+1:]...)
					e.RouteTables[id] = &n
					return nil, true, nil
				}
			}
		}
		return nil, true, errCode(ec2meta.CodeRTAssocNotFound, "the association ID '%s' does not exist", r.AssociationID)

	case opCreateNat:
		sn, ok := e.Subnets[r.SubnetID]
		if !ok || sn.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeSubnetNotFound, "the subnet ID '%s' does not exist", r.SubnetID)
		}
		a, ok := e.Addresses[r.AllocationID]
		if !ok || a.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeAllocationNotFound, "the allocation ID '%s' does not exist", r.AllocationID)
		}
		if a.Instance != "" || a.NatGateway != "" {
			return nil, true, errCode(ec2meta.CodeAddressInUse, "the address %s is already in use", a.PublicIP)
		}
		g := ec2meta.NatGateway{ID: rc.NewID, Tenant: c.Owner, VpcID: sn.VpcID, SubnetID: sn.ID, AllocationID: a.AllocationID,
			PublicIP: a.PublicIP, State: ec2meta.NatAvailable, Created: c.Now, Tags: r.Tags}
		e.NatGateways[g.ID] = &g
		na := *a
		na.NatGateway, na.AssociationID = g.ID, r.AssociationID
		e.Addresses[na.AllocationID] = &na
		return g, true, nil

	case opDeleteNat:
		g, ok := e.NatGateways[first(r.IDs)]
		if !ok || g.Tenant != c.Owner || g.State == ec2meta.NatDeleted {
			return nil, true, errCode(ec2meta.CodeNatNotFound, "the NAT gateway '%s' does not exist", first(r.IDs))
		}
		n := *g
		n.State, n.Deleted = ec2meta.NatDeleted, c.Now
		e.NatGateways[n.ID] = &n
		if a, ok := e.Addresses[n.AllocationID]; ok && a.NatGateway == n.ID {
			na := *a
			na.NatGateway, na.AssociationID = "", ""
			e.Addresses[na.AllocationID] = &na
		}
		// Routes to it now go nowhere (a blackhole, as on EC2).
		for _, sn := range e.NatGateways {
			if sn.State == ec2meta.NatDeleted && c.Now.Sub(sn.Deleted) > deletedNatLinger {
				delete(e.NatGateways, sn.ID)
			}
		}
		return n, true, nil
	}
	return nil, false, nil
}

// vpcEgress lists how a VPC's subnets that don't use the internet
// gateway reach the internet.
func vpcEgress(st *state, vpc string) []ec2meta.SubnetEgress {
	e := &st.EC2
	var out []ec2meta.SubnetEgress
	for _, sn := range e.Subnets {
		if sn.VpcID != vpc {
			continue
		}
		t := subnetTable(e, sn)
		if t == nil {
			continue
		}
		r := defaultRoute(t)
		if r != nil && r.Gateway != "" {
			continue // the internet gateway: each PC's own NAT
		}
		eg := ec2meta.SubnetEgress{CIDR: sn.CIDR, None: true}
		if r != nil {
			if g, ok := e.NatGateways[r.NatGateway]; ok && g.State == ec2meta.NatAvailable {
				if p, ok := e.PublicIPs[g.PublicIP]; ok {
					eg = ec2meta.SubnetEgress{CIDR: sn.CIDR, NAT: g.ID, PublicIP: g.PublicIP, Gateway: p.Node}
					if m, ok := st.Members[p.Node]; ok {
						eg.GatewayIP = m.MeshIP
					}
				}
			}
		}
		out = append(out, eg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDR < out[j].CIDR })
	return out
}

// natVPCs are the VPCs a PC holds a NAT gateway's address for.
func natVPCs(st *state, host string) []string {
	var out []string
	for _, g := range st.EC2.NatGateways {
		if p, ok := st.EC2.PublicIPs[g.PublicIP]; ok && g.State == ec2meta.NatAvailable && p.Node == host {
			out = append(out, g.VpcID)
		}
	}
	return out
}

// --- Server methods ---

func (s *Server) routeApply(op, action string, r ec2meta.RouteRequest, newID string) (any, error) {
	return s.ec2Apply(op, r.Tenant, ec2Command{Routes: &routeCommand{Req: r, NewID: newID}, Action: action})
}

// CreateRouteTable makes a route table in a VPC, with only the local route.
func (s *Server) CreateRouteTable(r ec2meta.RouteRequest) (*ec2meta.RouteTable, error) {
	ids, err := newIDs("rtb-")
	if err != nil {
		return nil, err
	}
	res, err := s.routeApply(opCreateRouteTable, "", r, ids[0])
	if err != nil {
		return nil, err
	}
	t := res.(ec2meta.RouteTable)
	return &t, nil
}

func (s *Server) DeleteRouteTable(r ec2meta.RouteRequest) error {
	_, err := s.routeApply(opDeleteRouteTable, "", r, "")
	return err
}

// SetRoute creates, replaces (r.Replace) or deletes (no r.Route) a
// table's default route.
func (s *Server) SetRoute(r ec2meta.RouteRequest) error {
	action := "set"
	if r.Route == nil {
		action = "delete"
	} else if r.Route.Destination != ec2meta.DefaultRoute {
		return errCode(ec2meta.CodeInvalidParameter, "only the %s route can be set (traffic inside the VPC always stays local)", ec2meta.DefaultRoute)
	}
	_, err := s.routeApply(opRoute, action, r, "")
	return err
}

// AssociateRouteTable makes a subnet use a table; it returns the
// association ID.
func (s *Server) AssociateRouteTable(r ec2meta.RouteRequest) (string, error) {
	ids, err := newIDs("rtbassoc-")
	if err != nil {
		return "", err
	}
	res, err := s.routeApply(opAssociateRT, "", r, ids[0])
	if err != nil {
		return "", err
	}
	return res.(string), nil
}

func (s *Server) DisassociateRouteTable(r ec2meta.RouteRequest) error {
	_, err := s.routeApply(opDisassociateRT, "", r, "")
	return err
}

// RouteTables lists a tenant's route tables, main ones included.
func (s *Server) RouteTables(r ec2meta.RouteRequest) ([]ec2meta.RouteTable, error) {
	if _, err := s.DefaultVPC(r.Tenant); err != nil {
		return nil, err
	}
	var out []ec2meta.RouteTable
	var err error
	s.fsm.view(func(st *state) {
		e := &st.EC2
		if len(r.IDs) > 0 {
			for _, id := range r.IDs {
				t, terr := routeTable(e, r.Tenant, id)
				if terr != nil {
					err = terr
					return
				}
				out = append(out, copyTable(t))
			}
			return
		}
		for _, v := range e.VPCs {
			if v.Tenant == r.Tenant && (r.VpcID == "" || v.ID == r.VpcID) {
				out = append(out, copyTable(mainTable(e, v)))
			}
		}
		for _, t := range e.RouteTables {
			if t.Tenant == r.Tenant && !t.Main && (r.VpcID == "" || t.VpcID == r.VpcID) {
				out = append(out, copyTable(t))
			}
		}
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Main != out[j].Main {
			return out[i].Main
		}
		return older(out[i].Created, out[i].ID, out[j].Created, out[j].ID)
	})
	return out, err
}

// CreateNatGateway puts a NAT gateway in a subnet, on an elastic IP.
func (s *Server) CreateNatGateway(r ec2meta.RouteRequest) (*ec2meta.NatGateway, error) {
	ids, err := newIDs("nat-", "eipassoc-")
	if err != nil {
		return nil, err
	}
	r.AssociationID = ids[1]
	res, err := s.routeApply(opCreateNat, "", r, ids[0])
	if err != nil {
		return nil, err
	}
	g := res.(ec2meta.NatGateway)
	return &g, nil
}

// DeleteNatGateway deletes a NAT gateway and frees its address.
func (s *Server) DeleteNatGateway(r ec2meta.RouteRequest) (*ec2meta.NatGateway, error) {
	res, err := s.routeApply(opDeleteNat, "", r, "")
	if err != nil {
		return nil, err
	}
	g := res.(ec2meta.NatGateway)
	return &g, nil
}

// NatGateways lists a tenant's NAT gateways (deleted ones for a while).
func (s *Server) NatGateways(r ec2meta.RouteRequest) ([]ec2meta.NatGateway, error) {
	var out []ec2meta.NatGateway
	var err error
	now := s.now()
	s.fsm.view(func(st *state) {
		for _, id := range r.IDs {
			if g, ok := st.EC2.NatGateways[id]; !ok || g.Tenant != r.Tenant {
				err = errCode(ec2meta.CodeNatNotFound, "the NAT gateway '%s' does not exist", id)
				return
			}
		}
		want := map[string]bool{}
		for _, id := range r.IDs {
			want[id] = true
		}
		for _, g := range st.EC2.NatGateways {
			if g.Tenant != r.Tenant || (len(want) > 0 && !want[g.ID]) {
				continue
			}
			if g.State == ec2meta.NatDeleted && now.Sub(g.Deleted) > deletedNatLinger {
				continue
			}
			out = append(out, *g)
		}
	})
	sort.Slice(out, func(i, j int) bool { return older(out[i].Created, out[i].ID, out[j].Created, out[j].ID) })
	return out, err
}

// --- HTTP ---

func (s *Server) routeRoutes(mux *http.ServeMux) {
	gw := func(h http.HandlerFunc) http.HandlerFunc { return s.requireGateway(s.leaderOnly(h)) }
	empty := func(fn func(ec2meta.RouteRequest) error) http.HandlerFunc {
		return jsonHandler(func(r ec2meta.RouteRequest) (struct{}, error) { return struct{}{}, fn(r) })
	}
	mux.HandleFunc("POST /v1/ec2/route-tables/create", gw(jsonHandler(s.CreateRouteTable)))
	mux.HandleFunc("POST /v1/ec2/route-tables/delete", gw(empty(s.DeleteRouteTable)))
	mux.HandleFunc("POST /v1/ec2/route-tables/route", gw(empty(s.SetRoute)))
	mux.HandleFunc("POST /v1/ec2/route-tables/associate", gw(jsonHandler(func(r ec2meta.RouteRequest) (struct {
		ID string `json:"id"`
	}, error) {
		id, err := s.AssociateRouteTable(r)
		return struct {
			ID string `json:"id"`
		}{id}, err
	})))
	mux.HandleFunc("POST /v1/ec2/route-tables/disassociate", gw(empty(s.DisassociateRouteTable)))
	mux.HandleFunc("POST /v1/ec2/route-tables/list", gw(jsonHandler(s.RouteTables)))
	mux.HandleFunc("POST /v1/ec2/nat-gateways/create", gw(jsonHandler(s.CreateNatGateway)))
	mux.HandleFunc("POST /v1/ec2/nat-gateways/delete", gw(jsonHandler(s.DeleteNatGateway)))
	mux.HandleFunc("POST /v1/ec2/nat-gateways/list", gw(jsonHandler(s.NatGateways)))
}
