package s3gw

import (
	"encoding/xml"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// VPCs, subnets and security groups in the EC2 API.

type vpcXML struct {
	ID        string    `xml:"vpcId"`
	State     string    `xml:"state"`
	CIDR      string    `xml:"cidrBlock"`
	CIDRs     []cidrXML `xml:"cidrBlockAssociationSet>item"`
	DHCP      string    `xml:"dhcpOptionsId"`
	Tenancy   string    `xml:"instanceTenancy"`
	IsDefault bool      `xml:"isDefault"`
	OwnerID   string    `xml:"ownerId"`
	Tags      []tagXML  `xml:"tagSet>item"`
}

type cidrXML struct {
	AssociationID string `xml:"associationId"`
	CIDR          string `xml:"cidrBlock"`
	State         struct {
		State string `xml:"state"`
	} `xml:"cidrBlockState"`
}

func toVPCXML(v ec2meta.VPC) vpcXML {
	c := cidrXML{AssociationID: "vpc-cidr-assoc-" + strings.TrimPrefix(v.ID, "vpc-"), CIDR: v.CIDR}
	c.State.State = "associated"
	return vpcXML{ID: v.ID, State: "available", CIDR: v.CIDR, CIDRs: []cidrXML{c}, DHCP: "default",
		Tenancy: "default", IsDefault: v.IsDefault, OwnerID: ownerID(v.Tenant), Tags: tagSet(v.Tags)}
}

type subnetXML struct {
	ID          string   `xml:"subnetId"`
	ARN         string   `xml:"subnetArn"`
	State       string   `xml:"state"`
	VpcID       string   `xml:"vpcId"`
	CIDR        string   `xml:"cidrBlock"`
	Available   int      `xml:"availableIpAddressCount"`
	Zone        string   `xml:"availabilityZone"`
	ZoneID      string   `xml:"availabilityZoneId"`
	DefaultAZ   bool     `xml:"defaultForAz"`
	MapPublicIP bool     `xml:"mapPublicIpOnLaunch"`
	OwnerID     string   `xml:"ownerId"`
	Tags        []tagXML `xml:"tagSet>item"`
}

func (g *Gateway) toSubnetXML(s ec2meta.Subnet, used int) subnetXML {
	avail := 0
	if p, err := netip.ParsePrefix(s.CIDR); err == nil {
		avail = 1<<(32-p.Bits()) - 5 - used
	}
	zone := s.Zone
	if zone == "" {
		zone = g.zone()
	}
	return subnetXML{ID: s.ID, ARN: "arn:aws:ec2:" + g.region() + ":" + ownerID(s.Tenant) + ":subnet/" + s.ID,
		State: "available", VpcID: s.VpcID, CIDR: s.CIDR, Available: avail, Zone: zone, ZoneID: "jy-" + zone,
		DefaultAZ: s.IsDefault, OwnerID: ownerID(s.Tenant), Tags: tagSet(s.Tags)}
}

type groupXML struct {
	OwnerID     string    `xml:"ownerId"`
	ID          string    `xml:"groupId"`
	Name        string    `xml:"groupName"`
	Description string    `xml:"groupDescription"`
	VpcID       string    `xml:"vpcId"`
	Ingress     []permXML `xml:"ipPermissions>item"`
	Egress      []permXML `xml:"ipPermissionsEgress>item"`
	Tags        []tagXML  `xml:"tagSet>item"`
}

type permXML struct {
	Protocol string `xml:"ipProtocol"`
	FromPort *int   `xml:"fromPort,omitempty"`
	ToPort   *int   `xml:"toPort,omitempty"`
	Groups   []struct {
		UserID  string `xml:"userId"`
		GroupID string `xml:"groupId"`
	} `xml:"groups>item"`
	Ranges []struct {
		CIDR string `xml:"cidrIp"`
	} `xml:"ipRanges>item"`
}

func toPermXML(tenant string, ps []ec2meta.Permission) []permXML {
	var out []permXML
	for _, p := range ps {
		x := permXML{Protocol: p.Protocol}
		if p.Protocol != "-1" {
			from, to := p.FromPort, p.ToPort
			x.FromPort, x.ToPort = &from, &to
		}
		for _, g := range p.Groups {
			x.Groups = append(x.Groups, struct {
				UserID  string `xml:"userId"`
				GroupID string `xml:"groupId"`
			}{ownerID(tenant), g})
		}
		for _, c := range p.CIDRs {
			x.Ranges = append(x.Ranges, struct {
				CIDR string `xml:"cidrIp"`
			}{c})
		}
		out = append(out, x)
	}
	return out
}

func toGroupXML(g ec2meta.SecurityGroup) groupXML {
	return groupXML{OwnerID: ownerID(g.Tenant), ID: g.ID, Name: g.Name, Description: g.Description, VpcID: g.VpcID,
		Ingress: toPermXML(g.Tenant, g.Ingress), Egress: toPermXML(g.Tenant, g.Egress), Tags: tagSet(g.Tags)}
}

// matchFilters checks EC2 filters against a record's named fields and tags.
func matchFilters(filters map[string][]string, fields map[string][]string, tags map[string]string) bool {
	for name, vals := range filters {
		var got []string
		switch {
		case name == "tag-key":
			for k := range tags {
				got = append(got, k)
			}
		case strings.HasPrefix(name, "tag:"):
			if v, ok := tags[name[4:]]; ok {
				got = []string{v}
			}
		default:
			f, ok := fields[name]
			if !ok {
				continue // unknown filters match everything
			}
			got = f
		}
		if !anyMatch(got, vals) {
			return false
		}
	}
	return true
}

func (g *Gateway) createVpc(q *request, p ec2Params) error {
	v, err := g.EC2.CreateVPC(q.ctx, ec2meta.VPCRequest{Tenant: q.tenant, CIDR: p.Get("CidrBlock"), Tags: emptyNil(p.tagSpecs("vpc"))})
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "CreateVpcResponse", struct {
		XMLName xml.Name `xml:"x"`
		VPC     vpcXML   `xml:"vpc"`
	}{VPC: toVPCXML(*v)})
}

func (g *Gateway) describeVpcs(q *request, p ec2Params) error {
	vs, err := g.EC2.VPCs(q.ctx, ec2meta.VPCRequest{Tenant: q.tenant, IDs: p.list("VpcId")})
	if err != nil {
		return err
	}
	filters := p.filters()
	var out []vpcXML
	for _, v := range vs {
		fields := map[string][]string{"vpc-id": {v.ID}, "cidr": {v.CIDR}, "cidr-block-association.cidr-block": {v.CIDR},
			"is-default": {strconv.FormatBool(v.IsDefault)}, "state": {"available"}, "owner-id": {ownerID(v.Tenant)}}
		if matchFilters(filters, fields, v.Tags) {
			out = append(out, toVPCXML(v))
		}
	}
	return g.ec2Reply(q, "DescribeVpcsResponse", struct {
		XMLName xml.Name `xml:"x"`
		VPCs    []vpcXML `xml:"vpcSet>item"`
	}{VPCs: out})
}

func (g *Gateway) createSubnet(q *request, p ec2Params) error {
	sn, err := g.EC2.CreateSubnet(q.ctx, ec2meta.SubnetRequest{Tenant: q.tenant, VpcID: p.Get("VpcId"), CIDR: p.Get("CidrBlock"),
		Zone: p.Get("AvailabilityZone"), Tags: emptyNil(p.tagSpecs("subnet"))})
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "CreateSubnetResponse", struct {
		XMLName xml.Name  `xml:"x"`
		Subnet  subnetXML `xml:"subnet"`
	}{Subnet: g.toSubnetXML(*sn, 0)})
}

func (g *Gateway) describeSubnets(q *request, p ec2Params) error {
	sns, err := g.EC2.Subnets(q.ctx, ec2meta.SubnetRequest{Tenant: q.tenant, IDs: p.list("SubnetId")})
	if err != nil {
		return err
	}
	ins, err := g.EC2.Instances(q.ctx, q.tenant, nil)
	if err != nil {
		return err
	}
	used := map[string]int{}
	for _, in := range ins {
		if in.State != ec2meta.StateTerminated {
			used[in.SubnetID]++
		}
	}
	filters := p.filters()
	var out []subnetXML
	for _, sn := range sns {
		x := g.toSubnetXML(sn, used[sn.ID])
		fields := map[string][]string{"subnet-id": {sn.ID}, "vpc-id": {sn.VpcID}, "cidr-block": {sn.CIDR}, "cidr": {sn.CIDR},
			"default-for-az": {strconv.FormatBool(sn.IsDefault)}, "availability-zone": {x.Zone}, "state": {"available"},
			"owner-id": {ownerID(sn.Tenant)}}
		if matchFilters(filters, fields, sn.Tags) {
			out = append(out, x)
		}
	}
	return g.ec2Reply(q, "DescribeSubnetsResponse", struct {
		XMLName xml.Name    `xml:"x"`
		Subnets []subnetXML `xml:"subnetSet>item"`
	}{Subnets: out})
}

func (g *Gateway) createSecurityGroup(q *request, p ec2Params) error {
	sg, err := g.EC2.CreateGroup(q.ctx, ec2meta.GroupRequest{Tenant: q.tenant, VpcID: p.Get("VpcId"), Name: p.Get("GroupName"),
		Description: p.Get("GroupDescription"), Tags: emptyNil(p.tagSpecs("security-group"))})
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "CreateSecurityGroupResponse", struct {
		XMLName xml.Name `xml:"x"`
		Return  bool     `xml:"return"`
		ID      string   `xml:"groupId"`
	}{Return: true, ID: sg.ID})
}

// groupID resolves GroupId, or GroupName in the default VPC.
func (g *Gateway) groupID(q *request, p ec2Params) (string, error) {
	if id := p.Get("GroupId"); id != "" {
		return id, nil
	}
	name := p.Get("GroupName")
	if name == "" {
		return "", ec2Err("MissingParameter", "GroupId or GroupName is required")
	}
	gs, err := g.EC2.Groups(q.ctx, ec2meta.GroupRequest{Tenant: q.tenant, Names: []string{name}})
	if err != nil {
		return "", err
	}
	return gs[0].ID, nil
}

func (g *Gateway) deleteSecurityGroup(q *request, p ec2Params) error {
	id, err := g.groupID(q, p)
	if err != nil {
		return err
	}
	if err := g.EC2.DeleteGroup(q.ctx, q.tenant, id); err != nil {
		return err
	}
	return g.ec2Return(q, "DeleteSecurityGroupResponse")
}

func (g *Gateway) describeSecurityGroups(q *request, p ec2Params) error {
	gs, err := g.EC2.Groups(q.ctx, ec2meta.GroupRequest{Tenant: q.tenant, IDs: p.list("GroupId"), Names: p.list("GroupName")})
	if err != nil {
		return err
	}
	filters := p.filters()
	var out []groupXML
	for _, sg := range gs {
		fields := map[string][]string{"group-id": {sg.ID}, "group-name": {sg.Name}, "vpc-id": {sg.VpcID},
			"description": {sg.Description}, "owner-id": {ownerID(sg.Tenant)}}
		if matchFilters(filters, fields, sg.Tags) {
			out = append(out, toGroupXML(sg))
		}
	}
	return g.ec2Reply(q, "DescribeSecurityGroupsResponse", struct {
		XMLName xml.Name   `xml:"x"`
		Groups  []groupXML `xml:"securityGroupInfo>item"`
	}{Groups: out})
}

// permissions parses IpPermissions.N, or the older flat form (IpProtocol,
// FromPort, ToPort, CidrIp, SourceSecurityGroupName).
func (g *Gateway) permissions(q *request, p ec2Params) ([]ec2meta.Permission, error) {
	port := func(s string) (int, error) {
		if s == "" {
			return -1, nil
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, ec2Err(ec2meta.CodeInvalidParameter, "bad port %q", s)
		}
		return n, nil
	}
	var out []ec2meta.Permission
	for i := 1; ; i++ {
		pre := "IpPermissions." + strconv.Itoa(i) + "."
		proto := p.Get(pre + "IpProtocol")
		if proto == "" {
			break
		}
		from, err := port(p.Get(pre + "FromPort"))
		if err != nil {
			return nil, err
		}
		to, err := port(p.Get(pre + "ToPort"))
		if err != nil {
			return nil, err
		}
		perm := ec2meta.Permission{Protocol: proto, FromPort: from, ToPort: to}
		for j := 1; ; j++ {
			c := p.Get(pre + "IpRanges." + strconv.Itoa(j) + ".CidrIp")
			if c == "" {
				break
			}
			perm.CIDRs = append(perm.CIDRs, c)
		}
		for j := 1; ; j++ {
			gp := pre + "Groups." + strconv.Itoa(j) + "."
			id, name := p.Get(gp+"GroupId"), p.Get(gp+"GroupName")
			if id == "" && name == "" {
				break
			}
			if id == "" {
				gs, err := g.EC2.Groups(q.ctx, ec2meta.GroupRequest{Tenant: q.tenant, Names: []string{name}})
				if err != nil {
					return nil, err
				}
				id = gs[0].ID
			}
			perm.Groups = append(perm.Groups, id)
		}
		if p.Get(pre+"Ipv6Ranges.1.CidrIpv6") != "" || p.Get(pre+"PrefixListIds.1.PrefixListId") != "" {
			return nil, ec2Err(ec2meta.CodeUnsupported, "IPv6 ranges and prefix lists are not supported")
		}
		out = append(out, perm)
	}
	if proto := p.Get("IpProtocol"); proto != "" {
		from, err := port(p.Get("FromPort"))
		if err != nil {
			return nil, err
		}
		to, err := port(p.Get("ToPort"))
		if err != nil {
			return nil, err
		}
		perm := ec2meta.Permission{Protocol: proto, FromPort: from, ToPort: to}
		if c := p.Get("CidrIp"); c != "" {
			perm.CIDRs = []string{c}
		}
		if name := p.Get("SourceSecurityGroupName"); name != "" {
			gs, err := g.EC2.Groups(q.ctx, ec2meta.GroupRequest{Tenant: q.tenant, Names: []string{name}})
			if err != nil {
				return nil, err
			}
			perm.Groups = []string{gs[0].ID}
		}
		out = append(out, perm)
	}
	if len(out) == 0 {
		return nil, ec2Err("MissingParameter", "no IpPermissions given")
	}
	return out, nil
}

func (g *Gateway) groupRules(q *request, p ec2Params, egress, revoke bool, name string) error {
	id, err := g.groupID(q, p)
	if err != nil {
		return err
	}
	perms, err := g.permissions(q, p)
	if err != nil {
		return err
	}
	if _, err := g.EC2.GroupRules(q.ctx, ec2meta.RulesRequest{Tenant: q.tenant, GroupID: id, Egress: egress, Revoke: revoke, Permissions: perms}); err != nil {
		return err
	}
	return g.ec2Return(q, name)
}
