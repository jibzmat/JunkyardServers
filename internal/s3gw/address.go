package s3gw

import (
	"encoding/xml"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// Elastic IPs in the EC2 API.

type addressXML struct {
	PublicIP      string   `xml:"publicIp"`
	AllocationID  string   `xml:"allocationId"`
	Domain        string   `xml:"domain"`
	InstanceID    string   `xml:"instanceId,omitempty"`
	AssociationID string   `xml:"associationId,omitempty"`
	PrivateIP     string   `xml:"privateIpAddress,omitempty"`
	OwnerID       string   `xml:"networkInterfaceOwnerId,omitempty"`
	Pool          string   `xml:"publicIpv4Pool"`
	BorderGroup   string   `xml:"networkBorderGroup"`
	Tags          []tagXML `xml:"tagSet>item"`
}

func (g *Gateway) toAddressXML(a ec2meta.Address) addressXML {
	x := addressXML{PublicIP: a.PublicIP, AllocationID: a.AllocationID, Domain: "vpc", InstanceID: a.Instance,
		AssociationID: a.AssociationID, PrivateIP: a.PrivateIP, Pool: "junkyard", BorderGroup: g.region(), Tags: tagSet(a.Tags)}
	if a.Instance != "" {
		x.OwnerID = ownerID(a.Tenant)
	}
	return x
}

func (g *Gateway) allocateAddress(q *request, p ec2Params) error {
	req := ec2meta.AddressRequest{Tenant: q.tenant, Tags: emptyNil(p.tagSpecs("elastic-ip"))}
	if ip := p.Get("Address"); ip != "" {
		req.PublicIPs = []string{ip}
	}
	a, err := g.EC2.AllocateAddress(q.ctx, req)
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "AllocateAddressResponse", struct {
		XMLName      xml.Name `xml:"x"`
		PublicIP     string   `xml:"publicIp"`
		Domain       string   `xml:"domain"`
		AllocationID string   `xml:"allocationId"`
		Pool         string   `xml:"publicIpv4Pool"`
		BorderGroup  string   `xml:"networkBorderGroup"`
	}{PublicIP: a.PublicIP, Domain: "vpc", AllocationID: a.AllocationID, Pool: "junkyard", BorderGroup: g.region()})
}

// addressRef reads the AllocationId or PublicIp naming an address.
func addressRef(q *request, p ec2Params) ec2meta.AddressRequest {
	req := ec2meta.AddressRequest{Tenant: q.tenant}
	if id := p.Get("AllocationId"); id != "" {
		req.AllocationIDs = []string{id}
	}
	if ip := p.Get("PublicIp"); ip != "" {
		req.PublicIPs = []string{ip}
	}
	return req
}

func (g *Gateway) associateAddress(q *request, p ec2Params) error {
	req := addressRef(q, p)
	if len(req.AllocationIDs) == 0 && len(req.PublicIPs) == 0 {
		return ec2Err("MissingParameter", "give AllocationId or PublicIp")
	}
	if p.Get("NetworkInterfaceId") != "" && p.Get("InstanceId") == "" {
		return ec2Err("InvalidParameterCombination", "associate with an instance (InstanceId); network interfaces are not supported")
	}
	req.Instance = p.Get("InstanceId")
	// Moving an address between instances needs AllowReassociation, as on
	// EC2 in a VPC.
	req.Reassociate = p.Get("AllowReassociation") == "true"
	a, err := g.EC2.AssociateAddress(q.ctx, req)
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "AssociateAddressResponse", struct {
		XMLName       xml.Name `xml:"x"`
		Return        bool     `xml:"return"`
		AssociationID string   `xml:"associationId"`
	}{Return: true, AssociationID: a.AssociationID})
}

func (g *Gateway) disassociateAddress(q *request, p ec2Params) error {
	req := ec2meta.AddressRequest{Tenant: q.tenant, AssociationID: p.Get("AssociationId")}
	if ip := p.Get("PublicIp"); ip != "" {
		req.PublicIPs = []string{ip}
	}
	if req.AssociationID == "" && len(req.PublicIPs) == 0 {
		return ec2Err("MissingParameter", "give AssociationId or PublicIp")
	}
	if err := g.EC2.DisassociateAddress(q.ctx, req); err != nil {
		return err
	}
	return g.ec2Return(q, "DisassociateAddressResponse")
}

func (g *Gateway) releaseAddress(q *request, p ec2Params) error {
	req := addressRef(q, p)
	if len(req.AllocationIDs) == 0 && len(req.PublicIPs) == 0 {
		return ec2Err("MissingParameter", "give AllocationId or PublicIp")
	}
	if err := g.EC2.ReleaseAddress(q.ctx, req); err != nil {
		return err
	}
	return g.ec2Return(q, "ReleaseAddressResponse")
}

func (g *Gateway) describeAddresses(q *request, p ec2Params) error {
	as, err := g.EC2.Addresses(q.ctx, ec2meta.AddressRequest{Tenant: q.tenant, AllocationIDs: p.list("AllocationId"), PublicIPs: p.list("PublicIp")})
	if err != nil {
		return err
	}
	filters := p.filters()
	var out []addressXML
	for _, a := range as {
		fields := map[string][]string{"allocation-id": {a.AllocationID}, "public-ip": {a.PublicIP}, "domain": {"vpc"},
			"instance-id": {a.Instance}, "association-id": {a.AssociationID}, "private-ip-address": {a.PrivateIP}}
		if matchFilters(filters, fields, a.Tags) {
			out = append(out, g.toAddressXML(a))
		}
	}
	return g.ec2Reply(q, "DescribeAddressesResponse", struct {
		XMLName   xml.Name     `xml:"x"`
		Addresses []addressXML `xml:"addressesSet>item"`
	}{Addresses: out})
}
