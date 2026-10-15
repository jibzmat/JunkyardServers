package s3gw

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// Route tables, NAT gateways and the (built-in) internet gateways in the
// EC2 API.

type routeXML struct {
	Destination string `xml:"destinationCidrBlock"`
	GatewayID   string `xml:"gatewayId,omitempty"`
	NatGateway  string `xml:"natGatewayId,omitempty"`
	State       string `xml:"state"`
	Origin      string `xml:"origin"`
}

type rtAssocXML struct {
	ID      string `xml:"routeTableAssociationId"`
	TableID string `xml:"routeTableId"`
	Subnet  string `xml:"subnetId,omitempty"`
	Main    bool   `xml:"main"`
	State   string `xml:"associationState>state"`
}

type routeTableXML struct {
	ID           string       `xml:"routeTableId"`
	VpcID        string       `xml:"vpcId"`
	OwnerID      string       `xml:"ownerId"`
	Routes       []routeXML   `xml:"routeSet>item"`
	Associations []rtAssocXML `xml:"associationSet>item"`
	Tags         []tagXML     `xml:"tagSet>item"`
}

// toRouteTableXML adds the local route (traffic inside the VPC) every
// table has, and marks routes to deleted NAT gateways as blackholes.
func toRouteTableXML(t ec2meta.RouteTable, vpcCIDR string, nats map[string]bool) routeTableXML {
	x := routeTableXML{ID: t.ID, VpcID: t.VpcID, OwnerID: ownerID(t.Tenant), Tags: tagSet(t.Tags)}
	if vpcCIDR != "" {
		x.Routes = append(x.Routes, routeXML{Destination: vpcCIDR, GatewayID: "local", State: "active", Origin: "CreateRouteTable"})
	}
	for _, r := range t.Routes {
		state := "active"
		if r.NatGateway != "" && !nats[r.NatGateway] {
			state = "blackhole"
		}
		x.Routes = append(x.Routes, routeXML{Destination: r.Destination, GatewayID: r.Gateway, NatGateway: r.NatGateway, State: state, Origin: "CreateRoute"})
	}
	if t.Main {
		x.Associations = append(x.Associations, rtAssocXML{ID: "rtbassoc-" + strings.TrimPrefix(t.ID, "rtb-"), TableID: t.ID, Main: true, State: "associated"})
	}
	for _, a := range t.Associations {
		x.Associations = append(x.Associations, rtAssocXML{ID: a.ID, TableID: t.ID, Subnet: a.Subnet, State: "associated"})
	}
	return x
}

// vpcCIDRs maps a tenant's VPCs to their address ranges.
func (g *Gateway) vpcCIDRs(q *request) (map[string]string, error) {
	vs, err := g.EC2.VPCs(q.ctx, ec2meta.VPCRequest{Tenant: q.tenant})
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, v := range vs {
		out[v.ID] = v.CIDR
	}
	return out, nil
}

// liveNats is the set of a tenant's NAT gateways that are available.
func (g *Gateway) liveNats(q *request) (map[string]bool, error) {
	ns, err := g.EC2.NatGateways(q.ctx, ec2meta.RouteRequest{Tenant: q.tenant})
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, n := range ns {
		if n.State == ec2meta.NatAvailable {
			out[n.ID] = true
		}
	}
	return out, nil
}

func (g *Gateway) createRouteTable(q *request, p ec2Params) error {
	t, err := g.EC2.CreateRouteTable(q.ctx, ec2meta.RouteRequest{Tenant: q.tenant, VpcID: p.Get("VpcId"), Tags: emptyNil(p.tagSpecs("route-table"))})
	if err != nil {
		return err
	}
	cidrs, err := g.vpcCIDRs(q)
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "CreateRouteTableResponse", struct {
		XMLName xml.Name      `xml:"x"`
		Table   routeTableXML `xml:"routeTable"`
	}{Table: toRouteTableXML(*t, cidrs[t.VpcID], nil)})
}

func (g *Gateway) deleteRouteTable(q *request, p ec2Params) error {
	if err := g.EC2.DeleteRouteTable(q.ctx, ec2meta.RouteRequest{Tenant: q.tenant, TableID: p.Get("RouteTableId")}); err != nil {
		return err
	}
	return g.ec2Return(q, "DeleteRouteTableResponse")
}

func (g *Gateway) describeRouteTables(q *request, p ec2Params) error {
	ts, err := g.EC2.RouteTables(q.ctx, ec2meta.RouteRequest{Tenant: q.tenant, IDs: p.list("RouteTableId")})
	if err != nil {
		return err
	}
	cidrs, err := g.vpcCIDRs(q)
	if err != nil {
		return err
	}
	nats, err := g.liveNats(q)
	if err != nil {
		return err
	}
	filters := p.filters()
	var out []routeTableXML
	for _, t := range ts {
		x := toRouteTableXML(t, cidrs[t.VpcID], nats)
		fields := map[string][]string{"route-table-id": {t.ID}, "vpc-id": {t.VpcID}, "owner-id": {x.OwnerID},
			"association.main": {strconv.FormatBool(t.Main)}}
		for _, a := range x.Associations {
			fields["association.route-table-association-id"] = append(fields["association.route-table-association-id"], a.ID)
			if a.Subnet != "" {
				fields["association.subnet-id"] = append(fields["association.subnet-id"], a.Subnet)
			}
		}
		for _, r := range x.Routes {
			fields["route.destination-cidr-block"] = append(fields["route.destination-cidr-block"], r.Destination)
			if r.GatewayID != "" {
				fields["route.gateway-id"] = append(fields["route.gateway-id"], r.GatewayID)
			}
			if r.NatGateway != "" {
				fields["route.nat-gateway-id"] = append(fields["route.nat-gateway-id"], r.NatGateway)
			}
		}
		if matchFilters(filters, fields, t.Tags) {
			out = append(out, x)
		}
	}
	return g.ec2Reply(q, "DescribeRouteTablesResponse", struct {
		XMLName xml.Name        `xml:"x"`
		Tables  []routeTableXML `xml:"routeTableSet>item"`
	}{Tables: out})
}

// setRoute is CreateRoute, ReplaceRoute and DeleteRoute.
func (g *Gateway) setRoute(q *request, p ec2Params, name string) error {
	req := ec2meta.RouteRequest{Tenant: q.tenant, TableID: p.Get("RouteTableId"), Replace: name == "ReplaceRouteResponse"}
	dest := p.Get("DestinationCidrBlock")
	if dest == "" {
		return ec2Err("MissingParameter", "give DestinationCidrBlock (IPv6 routes are not supported)")
	}
	if name != "DeleteRouteResponse" {
		r := ec2meta.Route{Destination: dest, Gateway: p.Get("GatewayId"), NatGateway: p.Get("NatGatewayId")}
		if (r.Gateway == "") == (r.NatGateway == "") {
			return ec2Err("InvalidParameterCombination", "give one of GatewayId (the VPC's internet gateway) or NatGatewayId")
		}
		req.Route = &r
	} else if dest != ec2meta.DefaultRoute {
		return ec2Err(ec2meta.CodeRouteNotFound, "no route to %s", dest)
	}
	if err := g.EC2.SetRoute(q.ctx, req); err != nil {
		return err
	}
	return g.ec2Return(q, name)
}

func (g *Gateway) associateRouteTable(q *request, p ec2Params) error {
	if p.Get("GatewayId") != "" {
		return ec2Err("InvalidParameterCombination", "route tables are associated with subnets here, not gateways")
	}
	id, err := g.EC2.AssociateRouteTable(q.ctx, ec2meta.RouteRequest{Tenant: q.tenant, TableID: p.Get("RouteTableId"), SubnetID: p.Get("SubnetId")})
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "AssociateRouteTableResponse", struct {
		XMLName xml.Name `xml:"x"`
		ID      string   `xml:"associationId"`
		State   string   `xml:"associationState>state"`
	}{ID: id, State: "associated"})
}

func (g *Gateway) disassociateRouteTable(q *request, p ec2Params) error {
	if err := g.EC2.DisassociateRouteTable(q.ctx, ec2meta.RouteRequest{Tenant: q.tenant, AssociationID: p.Get("AssociationId")}); err != nil {
		return err
	}
	return g.ec2Return(q, "DisassociateRouteTableResponse")
}

type natAddressXML struct {
	AllocationID  string `xml:"allocationId"`
	PublicIP      string `xml:"publicIp"`
	AssociationID string `xml:"associationId,omitempty"`
	Primary       bool   `xml:"isPrimary"`
	Status        string `xml:"status"`
}

type natGatewayXML struct {
	ID           string          `xml:"natGatewayId"`
	SubnetID     string          `xml:"subnetId"`
	VpcID        string          `xml:"vpcId"`
	State        string          `xml:"state"`
	Connectivity string          `xml:"connectivityType"`
	Created      string          `xml:"createTime"`
	Deleted      string          `xml:"deleteTime,omitempty"`
	Addresses    []natAddressXML `xml:"natGatewayAddressSet>item"`
	Tags         []tagXML        `xml:"tagSet>item"`
}

func toNatXML(n ec2meta.NatGateway) natGatewayXML {
	x := natGatewayXML{ID: n.ID, SubnetID: n.SubnetID, VpcID: n.VpcID, State: n.State, Connectivity: "public",
		Created: n.Created.UTC().Format(time.RFC3339), Tags: tagSet(n.Tags)}
	status := "succeeded"
	if n.State == ec2meta.NatDeleted {
		x.Deleted = n.Deleted.UTC().Format(time.RFC3339)
		status = "disassociated"
	}
	x.Addresses = []natAddressXML{{AllocationID: n.AllocationID, PublicIP: n.PublicIP, Primary: true, Status: status}}
	return x
}

func (g *Gateway) createNatGateway(q *request, p ec2Params) error {
	if t := p.Get("ConnectivityType"); t != "" && t != "public" {
		return ec2Err("InvalidParameterValue", "only public NAT gateways are supported")
	}
	if p.Get("AllocationId") == "" {
		return ec2Err("MissingParameter", "give AllocationId: a NAT gateway needs an elastic IP")
	}
	n, err := g.EC2.CreateNatGateway(q.ctx, ec2meta.RouteRequest{Tenant: q.tenant, SubnetID: p.Get("SubnetId"),
		AllocationID: p.Get("AllocationId"), Tags: emptyNil(p.tagSpecs("natgateway"))})
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "CreateNatGatewayResponse", struct {
		XMLName xml.Name      `xml:"x"`
		Token   string        `xml:"clientToken,omitempty"`
		Nat     natGatewayXML `xml:"natGateway"`
	}{Token: p.Get("ClientToken"), Nat: toNatXML(*n)})
}

func (g *Gateway) deleteNatGateway(q *request, p ec2Params) error {
	n, err := g.EC2.DeleteNatGateway(q.ctx, ec2meta.RouteRequest{Tenant: q.tenant, IDs: []string{p.Get("NatGatewayId")}})
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "DeleteNatGatewayResponse", struct {
		XMLName xml.Name `xml:"x"`
		ID      string   `xml:"natGatewayId"`
	}{ID: n.ID})
}

func (g *Gateway) describeNatGateways(q *request, p ec2Params) error {
	ns, err := g.EC2.NatGateways(q.ctx, ec2meta.RouteRequest{Tenant: q.tenant, IDs: p.list("NatGatewayId")})
	if err != nil {
		return err
	}
	filters := p.filters()
	var out []natGatewayXML
	for _, n := range ns {
		fields := map[string][]string{"nat-gateway-id": {n.ID}, "state": {n.State}, "subnet-id": {n.SubnetID}, "vpc-id": {n.VpcID}}
		if matchFilters(filters, fields, n.Tags) {
			out = append(out, toNatXML(n))
		}
	}
	return g.ec2Reply(q, "DescribeNatGatewaysResponse", struct {
		XMLName xml.Name        `xml:"x"`
		Nats    []natGatewayXML `xml:"natGatewaySet>item"`
	}{Nats: out})
}

type igwXML struct {
	ID          string `xml:"internetGatewayId"`
	OwnerID     string `xml:"ownerId"`
	Attachments []struct {
		VpcID string `xml:"vpcId"`
		State string `xml:"state"`
	} `xml:"attachmentSet>item"`
	Tags []tagXML `xml:"tagSet>item"`
}

// describeInternetGateways lists each VPC's internet gateway, which is
// always there and attached: instances reach the internet through the
// PC they run on.
func (g *Gateway) describeInternetGateways(q *request, p ec2Params) error {
	vs, err := g.EC2.VPCs(q.ctx, ec2meta.VPCRequest{Tenant: q.tenant})
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, id := range p.list("InternetGatewayId") {
		want[id] = true
	}
	filters := p.filters()
	var out []igwXML
	for _, v := range vs {
		id := ec2meta.InternetGateway(v.ID)
		if len(want) > 0 && !want[id] {
			continue
		}
		x := igwXML{ID: id, OwnerID: ownerID(v.Tenant)}
		x.Attachments = append(x.Attachments, struct {
			VpcID string `xml:"vpcId"`
			State string `xml:"state"`
		}{v.ID, "available"})
		fields := map[string][]string{"internet-gateway-id": {id}, "attachment.vpc-id": {v.ID}, "attachment.state": {"available"}, "owner-id": {x.OwnerID}}
		if matchFilters(filters, fields, nil) {
			out = append(out, x)
		}
	}
	return g.ec2Reply(q, "DescribeInternetGatewaysResponse", struct {
		XMLName  xml.Name `xml:"x"`
		Gateways []igwXML `xml:"internetGatewaySet>item"`
	}{Gateways: out})
}
