package control

import (
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// VPCs, subnets and security groups (M3). See docs/design.md.

const (
	opCreateVPC     = "create_vpc"
	opDeleteVPC     = "delete_vpc"
	opCreateSubnet  = "create_subnet"
	opDeleteSubnet  = "delete_subnet"
	opCreateGroup   = "create_group"
	opDeleteGroup   = "delete_group"
	opGroupRules    = "group_rules"
	opDefaultVPC    = "default_vpc"
	firstVNI        = 1000
	maxVNI          = 1<<24 - 1
	maxRulesPerSide = 60
)

// vpcCommand carries VPC operations inside an ec2Command.
type vpcCommand struct {
	VPC    *ec2meta.VPC           `json:"vpc,omitempty"`
	Subnet *ec2meta.Subnet        `json:"subnet,omitempty"`
	Group  *ec2meta.SecurityGroup `json:"group,omitempty"`
	Rules  *ec2meta.RulesRequest  `json:"rules,omitempty"`
}

// privateRanges are where VPC CIDRs may come from, as on EC2 (RFC 1918).
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

func validVPCCIDR(c string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(c)
	if err != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 28 || p.Masked() != p {
		return p, errCode(ec2meta.CodeVpcRange, "the CIDR '%s' is invalid: use a network address with a /16 to /28 mask", c)
	}
	for _, r := range privateRanges {
		if r.Contains(p.Addr()) && r.Bits() <= p.Bits() {
			return p, nil
		}
	}
	return p, errCode(ec2meta.CodeVpcRange, "the CIDR '%s' must be inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16", c)
}

func overlaps(a, b netip.Prefix) bool { return a.Overlaps(b) }

// applyVPC runs the VPC operations; anything else is not ours.
func (f *fsm) applyVPC(c command) (any, bool, error) {
	e := &f.st.EC2
	x := c.EC2
	v := x.Net
	switch c.Op {
	case opDefaultVPC:
		for _, vpc := range e.VPCs {
			if vpc.Tenant == c.Owner && vpc.IsDefault {
				return *vpc, true, nil
			}
		}
		fallthrough
	case opCreateVPC:
		if v == nil || v.VPC == nil || v.Group == nil {
			return nil, true, errCode(ec2meta.CodeInvalidParameter, "missing VPC")
		}
		if _, err := validVPCCIDR(v.VPC.CIDR); err != nil {
			return nil, true, err
		}
		if e.NextVNI < firstVNI {
			e.NextVNI = firstVNI
		}
		if e.NextVNI > maxVNI {
			return nil, true, errCode("VpcLimitExceeded", "no VXLAN identifiers left")
		}
		vpc := *v.VPC
		vpc.Tenant, vpc.Created, vpc.VNI = c.Owner, c.Now, e.NextVNI
		vpc.IsDefault = c.Op == opDefaultVPC
		e.NextVNI++
		e.VPCs[vpc.ID] = &vpc
		// Every VPC has a default group: members reach each other, and
		// everything may go out.
		g := *v.Group
		g.Tenant, g.VpcID, g.Created = c.Owner, vpc.ID, c.Now
		g.Name, g.Description = ec2meta.DefaultGroupName, "default VPC security group"
		g.Ingress = []ec2meta.Permission{{Protocol: "-1", FromPort: -1, ToPort: -1, Groups: []string{g.ID}}}
		g.Egress = []ec2meta.Permission{{Protocol: "-1", FromPort: -1, ToPort: -1, CIDRs: []string{"0.0.0.0/0"}}}
		e.Groups[g.ID] = &g
		if c.Op == opDefaultVPC && v.Subnet != nil {
			sn := *v.Subnet
			sn.Tenant, sn.VpcID, sn.Created, sn.IsDefault = c.Owner, vpc.ID, c.Now, true
			e.Subnets[sn.ID] = &sn
		}
		return vpc, true, nil

	case opDeleteVPC:
		vpc, ok := e.VPCs[v.VPC.ID]
		if !ok || vpc.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeVpcNotFound, "the vpc ID '%s' does not exist", v.VPC.ID)
		}
		for _, sn := range e.Subnets {
			if sn.VpcID == vpc.ID {
				return nil, true, errCode(ec2meta.CodeDependency, "the vpc '%s' has dependencies (subnet %s) and cannot be deleted", vpc.ID, sn.ID)
			}
		}
		for _, g := range e.Groups {
			if g.VpcID == vpc.ID && g.Name != ec2meta.DefaultGroupName {
				return nil, true, errCode(ec2meta.CodeDependency, "the vpc '%s' has dependencies (security group %s) and cannot be deleted", vpc.ID, g.ID)
			}
		}
		for id, g := range e.Groups {
			if g.VpcID == vpc.ID {
				delete(e.Groups, id)
			}
		}
		delete(e.VPCs, vpc.ID)
		return nil, true, nil

	case opCreateSubnet:
		sn := *v.Subnet
		vpc, ok := e.VPCs[sn.VpcID]
		if !ok || vpc.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeVpcNotFound, "the vpc ID '%s' does not exist", sn.VpcID)
		}
		p, err := netip.ParsePrefix(sn.CIDR)
		vp := netip.MustParsePrefix(vpc.CIDR)
		if err != nil || !p.Addr().Is4() || p.Masked() != p || p.Bits() < vp.Bits() || p.Bits() > 28 || !vp.Contains(p.Addr()) {
			return nil, true, errCode(ec2meta.CodeSubnetRange, "the CIDR '%s' is invalid for vpc %s (%s); subnets are /16 to /28 inside it", sn.CIDR, vpc.ID, vpc.CIDR)
		}
		for _, o := range e.Subnets {
			if o.VpcID == vpc.ID && overlaps(p, netip.MustParsePrefix(o.CIDR)) {
				return nil, true, errCode(ec2meta.CodeSubnetConflict, "the CIDR '%s' conflicts with subnet %s (%s)", sn.CIDR, o.ID, o.CIDR)
			}
		}
		sn.Tenant, sn.Created, sn.IsDefault = c.Owner, c.Now, false
		e.Subnets[sn.ID] = &sn
		return sn, true, nil

	case opDeleteSubnet:
		sn, ok := e.Subnets[v.Subnet.ID]
		if !ok || sn.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeSubnetNotFound, "the subnet ID '%s' does not exist", v.Subnet.ID)
		}
		for _, in := range e.Instances {
			if in.SubnetID == sn.ID && in.State != ec2meta.StateTerminated {
				return nil, true, errCode(ec2meta.CodeDependency, "the subnet '%s' has dependencies (instance %s) and cannot be deleted", sn.ID, in.ID)
			}
		}
		delete(e.Subnets, sn.ID)
		return nil, true, nil

	case opCreateGroup:
		g := *v.Group
		vpc, ok := e.VPCs[g.VpcID]
		if !ok || vpc.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeVpcNotFound, "the vpc ID '%s' does not exist", g.VpcID)
		}
		for _, o := range e.Groups {
			if o.VpcID == g.VpcID && o.Name == g.Name {
				return nil, true, errCode(ec2meta.CodeGroupDuplicate, "the security group '%s' already exists for VPC '%s'", g.Name, g.VpcID)
			}
		}
		g.Tenant, g.Created, g.Ingress = c.Owner, c.Now, nil
		g.Egress = []ec2meta.Permission{{Protocol: "-1", FromPort: -1, ToPort: -1, CIDRs: []string{"0.0.0.0/0"}}}
		e.Groups[g.ID] = &g
		return g, true, nil

	case opDeleteGroup:
		g, ok := e.Groups[v.Group.ID]
		if !ok || g.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeGroupNotFound, "the security group '%s' does not exist", v.Group.ID)
		}
		if g.Name == ec2meta.DefaultGroupName {
			return nil, true, errCode(ec2meta.CodeCannotDelete, "the default security group can't be deleted")
		}
		for _, in := range e.Instances {
			if in.State != ec2meta.StateTerminated && contains(in.SecurityGroups, g.ID) {
				return nil, true, errCode(ec2meta.CodeDependency, "resource %s has a dependent object (instance %s)", g.ID, in.ID)
			}
		}
		for _, o := range e.Groups {
			if o.ID == g.ID {
				continue
			}
			for _, p := range append(append([]ec2meta.Permission(nil), o.Ingress...), o.Egress...) {
				if contains(p.Groups, g.ID) {
					return nil, true, errCode(ec2meta.CodeDependency, "resource %s has a dependent object (rules of %s)", g.ID, o.ID)
				}
			}
		}
		delete(e.Groups, g.ID)
		return nil, true, nil

	case opGroupRules:
		r := v.Rules
		g, ok := e.Groups[r.GroupID]
		if !ok || g.Tenant != c.Owner {
			return nil, true, errCode(ec2meta.CodeGroupNotFound, "the security group '%s' does not exist", r.GroupID)
		}
		n := *g
		perms := &n.Ingress
		if r.Egress {
			perms = &n.Egress
		}
		next, err := changeRules(*perms, r.Permissions, r.Revoke)
		if err != nil {
			return nil, true, err
		}
		for _, p := range r.Permissions {
			for _, ref := range p.Groups {
				o, ok := e.Groups[ref]
				if !ok || o.Tenant != c.Owner || o.VpcID != g.VpcID {
					return nil, true, errCode(ec2meta.CodeGroupNotFound, "the security group '%s' does not exist in VPC '%s'", ref, g.VpcID)
				}
			}
		}
		*perms = next
		e.Groups[n.ID] = &n
		return n, true, nil
	}
	return nil, false, nil
}

// changeRules adds or removes sources of permissions. Each permission
// keeps its sources sorted; one with none left goes.
func changeRules(cur, change []ec2meta.Permission, revoke bool) ([]ec2meta.Permission, error) {
	out := make([]ec2meta.Permission, len(cur))
	for i, p := range cur {
		out[i] = ec2meta.Permission{Protocol: p.Protocol, FromPort: p.FromPort, ToPort: p.ToPort,
			CIDRs: append([]string(nil), p.CIDRs...), Groups: append([]string(nil), p.Groups...)}
	}
	for _, ch := range change {
		i := -1
		for j := range out {
			if out[j].Same(ch) {
				i = j
			}
		}
		if revoke {
			if i < 0 {
				return nil, errCode(ec2meta.CodePermissionNotFound, "the specified rule does not exist in this security group")
			}
			for _, c := range ch.CIDRs {
				if !contains(out[i].CIDRs, c) {
					return nil, errCode(ec2meta.CodePermissionNotFound, "the specified rule (%s) does not exist in this security group", c)
				}
				out[i].CIDRs = remove(out[i].CIDRs, c)
			}
			for _, g := range ch.Groups {
				if !contains(out[i].Groups, g) {
					return nil, errCode(ec2meta.CodePermissionNotFound, "the specified rule (%s) does not exist in this security group", g)
				}
				out[i].Groups = remove(out[i].Groups, g)
			}
			if len(out[i].CIDRs) == 0 && len(out[i].Groups) == 0 {
				out = append(out[:i], out[i+1:]...)
			}
			continue
		}
		if i < 0 {
			out = append(out, ec2meta.Permission{Protocol: ch.Protocol, FromPort: ch.FromPort, ToPort: ch.ToPort})
			i = len(out) - 1
		}
		for _, c := range ch.CIDRs {
			if contains(out[i].CIDRs, c) {
				return nil, errCode(ec2meta.CodePermissionDup, "the specified rule (%s %d-%d from %s) already exists", ch.Protocol, ch.FromPort, ch.ToPort, c)
			}
			out[i].CIDRs = append(out[i].CIDRs, c)
		}
		for _, g := range ch.Groups {
			if contains(out[i].Groups, g) {
				return nil, errCode(ec2meta.CodePermissionDup, "the specified rule (%s %d-%d from %s) already exists", ch.Protocol, ch.FromPort, ch.ToPort, g)
			}
			out[i].Groups = append(out[i].Groups, g)
		}
		sort.Strings(out[i].CIDRs)
		sort.Strings(out[i].Groups)
	}
	if len(out) > maxRulesPerSide {
		return nil, errCode("RulesPerSecurityGroupLimitExceeded", "a group may have at most %d permissions each way", maxRulesPerSide)
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func remove(list []string, s string) []string {
	var out []string
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// instanceIP picks the lowest free address of a subnet. Terminated
// instances' addresses are free again.
func instanceIP(e *ec2State, sn *ec2meta.Subnet, taken map[string]bool) (string, error) {
	first, last, err := ec2meta.UsableRange(sn.CIDR)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	for _, in := range e.Instances {
		if in.SubnetID == sn.ID && in.State != ec2meta.StateTerminated {
			used[in.PrivateIP] = true
		}
	}
	for a := first; a.Compare(last) <= 0; a = a.Next() {
		if !used[a.String()] && !taken[a.String()] {
			return a.String(), nil
		}
	}
	return "", errCode(ec2meta.CodeNoFreeAddresses, "subnet %s has no free addresses", sn.ID)
}

// vpcNet is what host needs to run its instances of a VPC.
func vpcNet(st *state, id, host string) (ec2meta.VPCNet, bool) {
	vpc, ok := st.EC2.VPCs[id]
	if !ok {
		return ec2meta.VPCNet{}, false
	}
	n := ec2meta.VPCNet{VPC: *vpc, Members: map[string][]string{}}
	for _, sn := range st.EC2.Subnets {
		if sn.VpcID == id {
			n.Subnets = append(n.Subnets, *sn)
		}
	}
	local := map[string]bool{}
	members := map[string][]string{}
	for _, in := range st.EC2.Instances {
		if in.VpcID != id || in.State == ec2meta.StateTerminated {
			continue
		}
		for _, g := range in.SecurityGroups {
			members[g] = append(members[g], in.PrivateIP)
		}
		if in.Host == "" {
			continue
		}
		hostIP := ""
		if m, ok := st.Members[in.Host]; ok {
			hostIP = m.MeshIP
		}
		ep := ec2meta.Endpoint{Instance: in.ID, IP: in.PrivateIP, MAC: in.MAC, Host: in.Host, HostIP: hostIP}
		if in.Host == host {
			ep.Groups = in.SecurityGroups
		}
		n.Endpoints = append(n.Endpoints, ep)
		if in.Host == host {
			for _, g := range in.SecurityGroups {
				local[g] = true
			}
		}
	}
	refs := map[string]bool{}
	for gid := range local {
		g, ok := st.EC2.Groups[gid]
		if !ok {
			continue
		}
		n.Groups = append(n.Groups, *g)
		for _, p := range append(append([]ec2meta.Permission(nil), g.Ingress...), g.Egress...) {
			for _, r := range p.Groups {
				refs[r] = true
			}
		}
	}
	for r := range refs {
		ips := members[r]
		sort.Strings(ips)
		n.Members[r] = ips
	}
	n.EIPs = vpcEIPs(st, id)
	sort.Slice(n.Subnets, func(i, j int) bool { return n.Subnets[i].ID < n.Subnets[j].ID })
	sort.Slice(n.Endpoints, func(i, j int) bool { return n.Endpoints[i].Instance < n.Endpoints[j].Instance })
	sort.Slice(n.Groups, func(i, j int) bool { return n.Groups[i].ID < n.Groups[j].ID })
	return n, true
}

// --- Server methods ---

func (s *Server) vpcApply(op, tenant string, v vpcCommand) (any, error) {
	return s.ec2Apply(op, tenant, ec2Command{Net: &v})
}

func newIDs(prefixes ...string) ([]string, error) {
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		id, err := randString(p, hexDigits, 17)
		if err != nil {
			return nil, err
		}
		out[i] = id
	}
	return out, nil
}

// DefaultVPC returns the tenant's default VPC, making it (with its default
// subnet and group) on first use.
func (s *Server) DefaultVPC(tenant string) (*ec2meta.VPC, error) {
	var found *ec2meta.VPC
	s.fsm.view(func(st *state) {
		for _, v := range st.EC2.VPCs {
			if v.Tenant == tenant && v.IsDefault {
				c := *v
				found = &c
			}
		}
	})
	if found != nil {
		return found, nil
	}
	ids, err := newIDs("vpc-", "subnet-", "sg-")
	if err != nil {
		return nil, err
	}
	res, err := s.vpcApply(opDefaultVPC, tenant, vpcCommand{
		VPC:    &ec2meta.VPC{ID: ids[0], CIDR: ec2meta.DefaultVPCCIDR},
		Subnet: &ec2meta.Subnet{ID: ids[1], CIDR: ec2meta.DefaultSubnetCIDR},
		Group:  &ec2meta.SecurityGroup{ID: ids[2]},
	})
	if err != nil {
		return nil, err
	}
	v := res.(ec2meta.VPC)
	return &v, nil
}

// CreateVPC makes a VPC and its default security group.
func (s *Server) CreateVPC(req ec2meta.VPCRequest) (*ec2meta.VPC, error) {
	if _, err := validVPCCIDR(req.CIDR); err != nil {
		return nil, err
	}
	if _, err := s.DefaultVPC(req.Tenant); err != nil {
		return nil, err
	}
	ids, err := newIDs("vpc-", "sg-")
	if err != nil {
		return nil, err
	}
	res, err := s.vpcApply(opCreateVPC, req.Tenant, vpcCommand{
		VPC:   &ec2meta.VPC{ID: ids[0], CIDR: req.CIDR, Tags: req.Tags},
		Group: &ec2meta.SecurityGroup{ID: ids[1]},
	})
	if err != nil {
		return nil, err
	}
	v := res.(ec2meta.VPC)
	return &v, nil
}

// DeleteVPC deletes a VPC with no subnets or groups left.
func (s *Server) DeleteVPC(tenant, id string) error {
	_, err := s.vpcApply(opDeleteVPC, tenant, vpcCommand{VPC: &ec2meta.VPC{ID: id}})
	return err
}

// VPCs lists a tenant's VPCs, or the ones named.
func (s *Server) VPCs(req ec2meta.VPCRequest) ([]ec2meta.VPC, error) {
	if _, err := s.DefaultVPC(req.Tenant); err != nil {
		return nil, err
	}
	var out []ec2meta.VPC
	err := s.list(req.IDs, ec2meta.CodeVpcNotFound, "vpc ID", func(st *state, id string) (bool, func()) {
		v, ok := st.EC2.VPCs[id]
		return ok && v.Tenant == req.Tenant, func() { out = append(out, *v) }
	}, func(st *state) {
		for _, v := range st.EC2.VPCs {
			if v.Tenant == req.Tenant {
				out = append(out, *v)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return older(out[i].Created, out[i].ID, out[j].Created, out[j].ID) })
	return out, err
}

// list runs one of two views: of the named IDs (failing on an unknown
// one), or of all.
func (s *Server) list(ids []string, code, what string, one func(*state, string) (bool, func()), all func(*state)) error {
	var err error
	s.fsm.view(func(st *state) {
		if len(ids) == 0 {
			all(st)
			return
		}
		var adds []func()
		for _, id := range ids {
			ok, add := one(st, id)
			if !ok {
				err = errCode(code, "the %s '%s' does not exist", what, id)
				return
			}
			adds = append(adds, add)
		}
		for _, a := range adds {
			a()
		}
	})
	return err
}

// CreateSubnet makes a subnet in a VPC.
func (s *Server) CreateSubnet(req ec2meta.SubnetRequest) (*ec2meta.Subnet, error) {
	ids, err := newIDs("subnet-")
	if err != nil {
		return nil, err
	}
	res, err := s.vpcApply(opCreateSubnet, req.Tenant, vpcCommand{
		Subnet: &ec2meta.Subnet{ID: ids[0], VpcID: req.VpcID, CIDR: req.CIDR, Zone: req.Zone, Tags: req.Tags},
	})
	if err != nil {
		return nil, err
	}
	sn := res.(ec2meta.Subnet)
	return &sn, nil
}

// DeleteSubnet deletes a subnet with no instances.
func (s *Server) DeleteSubnet(tenant, id string) error {
	_, err := s.vpcApply(opDeleteSubnet, tenant, vpcCommand{Subnet: &ec2meta.Subnet{ID: id}})
	return err
}

// Subnets lists a tenant's subnets, or the ones named.
func (s *Server) Subnets(req ec2meta.SubnetRequest) ([]ec2meta.Subnet, error) {
	if _, err := s.DefaultVPC(req.Tenant); err != nil {
		return nil, err
	}
	var out []ec2meta.Subnet
	err := s.list(req.IDs, ec2meta.CodeSubnetNotFound, "subnet ID", func(st *state, id string) (bool, func()) {
		v, ok := st.EC2.Subnets[id]
		return ok && v.Tenant == req.Tenant, func() { out = append(out, *v) }
	}, func(st *state) {
		for _, v := range st.EC2.Subnets {
			if v.Tenant == req.Tenant && (req.VpcID == "" || v.VpcID == req.VpcID) {
				out = append(out, *v)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return older(out[i].Created, out[i].ID, out[j].Created, out[j].ID) })
	return out, err
}

// CreateGroup makes a security group in a VPC (the default VPC if none).
func (s *Server) CreateGroup(req ec2meta.GroupRequest) (*ec2meta.SecurityGroup, error) {
	if req.Name == "" || len(req.Name) > 255 || req.Name == ec2meta.DefaultGroupName || len(req.Name) > 3 && req.Name[:3] == "sg-" {
		return nil, errCode(ec2meta.CodeInvalidParameter, "a group name must be 1 to 255 characters, not 'default' and not start with sg-")
	}
	if req.Description == "" || len(req.Description) > 255 {
		return nil, errCode("MissingParameter", "a group needs a description of 1 to 255 characters")
	}
	if req.VpcID == "" {
		v, err := s.DefaultVPC(req.Tenant)
		if err != nil {
			return nil, err
		}
		req.VpcID = v.ID
	}
	ids, err := newIDs("sg-")
	if err != nil {
		return nil, err
	}
	res, err := s.vpcApply(opCreateGroup, req.Tenant, vpcCommand{
		Group: &ec2meta.SecurityGroup{ID: ids[0], VpcID: req.VpcID, Name: req.Name, Description: req.Description, Tags: req.Tags},
	})
	if err != nil {
		return nil, err
	}
	g := res.(ec2meta.SecurityGroup)
	return &g, nil
}

// DeleteGroup deletes a group no instance or rule uses.
func (s *Server) DeleteGroup(tenant, id string) error {
	_, err := s.vpcApply(opDeleteGroup, tenant, vpcCommand{Group: &ec2meta.SecurityGroup{ID: id}})
	return err
}

// Groups lists a tenant's security groups: all, or by ID or name.
func (s *Server) Groups(req ec2meta.GroupRequest) ([]ec2meta.SecurityGroup, error) {
	def, err := s.DefaultVPC(req.Tenant)
	if err != nil {
		return nil, err
	}
	var out []ec2meta.SecurityGroup
	err = s.list(req.IDs, ec2meta.CodeGroupNotFound, "security group", func(st *state, id string) (bool, func()) {
		g, ok := st.EC2.Groups[id]
		return ok && g.Tenant == req.Tenant, func() { out = append(out, *g) }
	}, func(st *state) {
		for _, g := range st.EC2.Groups {
			if g.Tenant == req.Tenant && (req.VpcID == "" || g.VpcID == req.VpcID) {
				out = append(out, *g)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if len(req.Names) > 0 {
		// Names are looked up in the default VPC, as EC2 does.
		var named []ec2meta.SecurityGroup
		for _, n := range req.Names {
			found := false
			for _, g := range out {
				if g.Name == n && g.VpcID == def.ID {
					named, found = append(named, g), true
				}
			}
			if !found {
				return nil, errCode(ec2meta.CodeGroupNotFound, "the security group '%s' does not exist in default VPC '%s'", n, def.ID)
			}
		}
		out = named
	}
	sort.Slice(out, func(i, j int) bool { return older(out[i].Created, out[i].ID, out[j].Created, out[j].ID) })
	return out, nil
}

// GroupRules authorizes or revokes permissions.
func (s *Server) GroupRules(req ec2meta.RulesRequest) (*ec2meta.SecurityGroup, error) {
	if len(req.Permissions) == 0 {
		return nil, errCode("MissingParameter", "no permissions given")
	}
	for i := range req.Permissions {
		if err := req.Permissions[i].Normalize(); err != nil {
			return nil, errCode(ec2meta.CodeInvalidParameter, "%v", err)
		}
	}
	res, err := s.vpcApply(opGroupRules, req.Tenant, vpcCommand{Rules: &req})
	if err != nil {
		return nil, err
	}
	g := res.(ec2meta.SecurityGroup)
	return &g, nil
}

// --- HTTP ---

func (s *Server) vpcRoutes(mux *http.ServeMux) {
	gw := func(h http.HandlerFunc) http.HandlerFunc { return s.requireGateway(s.leaderOnly(h)) }
	mux.HandleFunc("POST /v1/ec2/vpcs/create", gw(jsonHandler(s.CreateVPC)))
	mux.HandleFunc("POST /v1/ec2/vpcs/delete", gw(jsonHandler(func(r ec2meta.VPCRequest) (struct{}, error) {
		return struct{}{}, s.DeleteVPC(r.Tenant, first(r.IDs))
	})))
	mux.HandleFunc("POST /v1/ec2/vpcs/list", gw(jsonHandler(s.VPCs)))
	mux.HandleFunc("POST /v1/ec2/subnets/create", gw(jsonHandler(s.CreateSubnet)))
	mux.HandleFunc("POST /v1/ec2/subnets/delete", gw(jsonHandler(func(r ec2meta.SubnetRequest) (struct{}, error) {
		return struct{}{}, s.DeleteSubnet(r.Tenant, first(r.IDs))
	})))
	mux.HandleFunc("POST /v1/ec2/subnets/list", gw(jsonHandler(s.Subnets)))
	mux.HandleFunc("POST /v1/ec2/groups/create", gw(jsonHandler(s.CreateGroup)))
	mux.HandleFunc("POST /v1/ec2/groups/delete", gw(jsonHandler(func(r ec2meta.GroupRequest) (struct{}, error) {
		return struct{}{}, s.DeleteGroup(r.Tenant, first(r.IDs))
	})))
	mux.HandleFunc("POST /v1/ec2/groups/list", gw(jsonHandler(s.Groups)))
	mux.HandleFunc("POST /v1/ec2/groups/rules", gw(jsonHandler(s.GroupRules)))
}

func first(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

// jsonHandler adapts a method taking and returning JSON values.
func jsonHandler[Req, Resp any](fn func(Req) (Resp, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Req
		if !decode(w, r, &req) {
			return
		}
		resp, err := fn(req)
		if err != nil {
			metaError(w, err)
			return
		}
		writeJSON(w, resp)
	}
}

// older orders records by creation time, then ID.
func older(a time.Time, aid string, b time.Time, bid string) bool {
	if !a.Equal(b) {
		return a.Before(b)
	}
	return aid < bid
}
