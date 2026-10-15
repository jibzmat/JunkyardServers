package s3gw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
)

// The EC2 API: the Query protocol (form-encoded actions, XML replies),
// signed with SigV4 for the "ec2" service, served on the same port as S3.

// EC2Meta is the control plane's EC2 API; *control.Client implements it.
type EC2Meta interface {
	RunInstances(ctx context.Context, tenant string, req ec2meta.RunRequest) (*ec2meta.RunResponse, error)
	Instances(ctx context.Context, tenant string, ids []string) ([]ec2meta.Instance, error)
	InstanceAction(ctx context.Context, tenant, action string, ids []string) (*ec2meta.ChangeResponse, error)
	PutKeyPair(ctx context.Context, tenant string, k ec2meta.KeyPair) (*ec2meta.KeyPair, error)
	DeleteKeyPair(ctx context.Context, tenant, name string) error
	KeyPairs(ctx context.Context, tenant string, names []string) ([]ec2meta.KeyPair, error)
	PutImage(ctx context.Context, tenant string, img ec2meta.Image, obj s3meta.Object) (*ec2meta.Image, error)
	DeleteImage(ctx context.Context, tenant, id string) (*s3meta.Object, error)
	Images(ctx context.Context, tenant string, ids []string) ([]ec2meta.Image, error)
	Tags(ctx context.Context, req ec2meta.TagsRequest) error

	CreateVolume(ctx context.Context, tenant string, v ec2meta.Volume) (*ec2meta.Volume, error)
	DeleteVolume(ctx context.Context, tenant, id string) error
	AttachVolume(ctx context.Context, req ec2meta.AttachRequest) (*ec2meta.Volume, error)
	DetachVolume(ctx context.Context, req ec2meta.AttachRequest) (*ec2meta.Volume, error)
	Volumes(ctx context.Context, tenant string, ids []string) ([]ec2meta.Volume, error)
	CreateSnapshot(ctx context.Context, tenant, volume, description string, tags map[string]string) (*ec2meta.Snapshot, error)
	DeleteSnapshot(ctx context.Context, tenant, id string) (*s3meta.Object, error)
	Snapshots(ctx context.Context, tenant string, ids []string) ([]ec2meta.Snapshot, error)
	CreateImage(ctx context.Context, req ec2meta.CreateImageRequest) (*ec2meta.Image, error)
	Console(ctx context.Context, tenant, id string) (*ec2meta.ConsoleOutput, error)

	CreateVPC(ctx context.Context, req ec2meta.VPCRequest) (*ec2meta.VPC, error)
	DeleteVPC(ctx context.Context, tenant, id string) error
	VPCs(ctx context.Context, req ec2meta.VPCRequest) ([]ec2meta.VPC, error)
	CreateSubnet(ctx context.Context, req ec2meta.SubnetRequest) (*ec2meta.Subnet, error)
	DeleteSubnet(ctx context.Context, tenant, id string) error
	Subnets(ctx context.Context, req ec2meta.SubnetRequest) ([]ec2meta.Subnet, error)
	CreateGroup(ctx context.Context, req ec2meta.GroupRequest) (*ec2meta.SecurityGroup, error)
	DeleteGroup(ctx context.Context, tenant, id string) error
	Groups(ctx context.Context, req ec2meta.GroupRequest) ([]ec2meta.SecurityGroup, error)
	GroupRules(ctx context.Context, req ec2meta.RulesRequest) (*ec2meta.SecurityGroup, error)

	AllocateAddress(ctx context.Context, req ec2meta.AddressRequest) (*ec2meta.Address, error)
	ReleaseAddress(ctx context.Context, req ec2meta.AddressRequest) error
	AssociateAddress(ctx context.Context, req ec2meta.AddressRequest) (*ec2meta.Address, error)
	DisassociateAddress(ctx context.Context, req ec2meta.AddressRequest) error
	Addresses(ctx context.Context, req ec2meta.AddressRequest) ([]ec2meta.Address, error)

	CreateRouteTable(ctx context.Context, req ec2meta.RouteRequest) (*ec2meta.RouteTable, error)
	DeleteRouteTable(ctx context.Context, req ec2meta.RouteRequest) error
	SetRoute(ctx context.Context, req ec2meta.RouteRequest) error
	AssociateRouteTable(ctx context.Context, req ec2meta.RouteRequest) (string, error)
	DisassociateRouteTable(ctx context.Context, req ec2meta.RouteRequest) error
	RouteTables(ctx context.Context, req ec2meta.RouteRequest) ([]ec2meta.RouteTable, error)
	CreateNatGateway(ctx context.Context, req ec2meta.RouteRequest) (*ec2meta.NatGateway, error)
	DeleteNatGateway(ctx context.Context, req ec2meta.RouteRequest) (*ec2meta.NatGateway, error)
	NatGateways(ctx context.Context, req ec2meta.RouteRequest) ([]ec2meta.NatGateway, error)
}

const ec2NS = "http://ec2.amazonaws.com/doc/2016-11-15/"

// PlacementTag is the tag that picks an instance's placement at launch.
const PlacementTag = "jy:placement"

// isEC2 reports whether a request is signed for the EC2 service, so its
// errors can be sent in EC2's format even before it is verified.
func isEC2(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if i := strings.Index(h, "Credential="); i >= 0 {
		cred, _, _ := strings.Cut(h[i+len("Credential="):], ",")
		return scopeService(cred) == "ec2"
	}
	return scopeService(r.URL.Query().Get("X-Amz-Credential")) == "ec2"
}

type ec2Params struct{ url.Values }

func (p ec2Params) list(prefix string) []string {
	var out []string
	for i := 1; ; i++ {
		v, ok := p.Values[prefix+"."+strconv.Itoa(i)]
		if !ok {
			return out
		}
		out = append(out, v[0])
	}
}

// filters parses Filter.N.Name / Filter.N.Value.M.
func (p ec2Params) filters() map[string][]string {
	out := map[string][]string{}
	for i := 1; ; i++ {
		name := p.Get("Filter." + strconv.Itoa(i) + ".Name")
		if name == "" {
			return out
		}
		out[name] = append(out[name], p.list("Filter."+strconv.Itoa(i)+".Value")...)
	}
}

// tagSpecs parses TagSpecification.N for the given resource type.
func (p ec2Params) tagSpecs(resource string) map[string]string {
	tags := map[string]string{}
	for i := 1; ; i++ {
		pre := "TagSpecification." + strconv.Itoa(i)
		rt := p.Get(pre + ".ResourceType")
		if rt == "" {
			break
		}
		if rt != resource {
			continue
		}
		for j := 1; ; j++ {
			k := p.Get(pre + ".Tag." + strconv.Itoa(j) + ".Key")
			if k == "" {
				break
			}
			tags[k] = p.Get(pre + ".Tag." + strconv.Itoa(j) + ".Value")
		}
	}
	return tags
}

// tags parses Tag.N.Key / Tag.N.Value.
func (p ec2Params) tags() map[string]string {
	out := map[string]string{}
	for j := 1; ; j++ {
		k := p.Get("Tag." + strconv.Itoa(j) + ".Key")
		if k == "" {
			return out
		}
		out[k] = p.Get("Tag." + strconv.Itoa(j) + ".Value")
	}
}

func ec2Err(code, format string, args ...any) *Error {
	return errf(code, http.StatusBadRequest, format, args...)
}

func (g *Gateway) serveEC2(q *request) error {
	if g.EC2 == nil {
		return errf("UnsupportedOperation", http.StatusBadRequest, "this gateway does not serve the EC2 API")
	}
	if q.r.Method != http.MethodPost && q.r.Method != http.MethodGet {
		return ec2Err("InvalidAction", "use POST")
	}
	if err := q.r.ParseForm(); err != nil {
		return ec2Err("MalformedQueryString", "%v", err)
	}
	p := ec2Params{q.r.Form}
	switch p.Get("Action") {
	case "DescribeRegions":
		return g.describeRegions(q)
	case "DescribeAvailabilityZones":
		return g.describeZones(q)
	case "DescribeInstanceTypes":
		return g.describeInstanceTypes(q, p)
	case "RunInstances":
		return g.runInstances(q, p)
	case "DescribeInstances":
		return g.describeInstances(q, p)
	case "DescribeInstanceStatus":
		return g.describeInstanceStatus(q, p)
	case "StopInstances":
		return g.instanceAction(q, p, "stop", "StopInstancesResponse")
	case "StartInstances":
		return g.instanceAction(q, p, "start", "StartInstancesResponse")
	case "TerminateInstances":
		return g.instanceAction(q, p, "terminate", "TerminateInstancesResponse")
	case "RebootInstances":
		if _, err := g.EC2.InstanceAction(q.ctx, q.tenant, "reboot", p.list("InstanceId")); err != nil {
			return err
		}
		return g.ec2Return(q, "RebootInstancesResponse")
	case "CreateKeyPair":
		return g.createKeyPair(q, p)
	case "ImportKeyPair":
		return g.importKeyPair(q, p)
	case "DescribeKeyPairs":
		return g.describeKeyPairs(q, p)
	case "DeleteKeyPair":
		if err := g.EC2.DeleteKeyPair(q.ctx, q.tenant, p.Get("KeyName")); err != nil {
			return err
		}
		return g.ec2Return(q, "DeleteKeyPairResponse")
	case "RegisterImage":
		return g.registerImage(q, p)
	case "DescribeImages":
		return g.describeImages(q, p)
	case "DeregisterImage":
		old, err := g.EC2.DeleteImage(q.ctx, q.tenant, p.Get("ImageId"))
		if err != nil {
			return err
		}
		if old != nil {
			g.discard(old.Segments()...)
		}
		return g.ec2Return(q, "DeregisterImageResponse")
	case "CreateTags", "DeleteTags":
		req := ec2meta.TagsRequest{Tenant: q.tenant, Resources: p.list("ResourceId"), Tags: p.tags(), Delete: p.Get("Action") == "DeleteTags"}
		if err := g.EC2.Tags(q.ctx, req); err != nil {
			return err
		}
		return g.ec2Return(q, p.Get("Action")+"Response")
	case "CreateVolume":
		return g.createVolume(q, p)
	case "DeleteVolume":
		if err := g.EC2.DeleteVolume(q.ctx, q.tenant, p.Get("VolumeId")); err != nil {
			return err
		}
		return g.ec2Return(q, "DeleteVolumeResponse")
	case "AttachVolume", "DetachVolume":
		return g.attachVolume(q, p)
	case "DescribeVolumes":
		return g.describeVolumes(q, p)
	case "CreateSnapshot":
		return g.createSnapshot(q, p)
	case "DeleteSnapshot":
		old, err := g.EC2.DeleteSnapshot(q.ctx, q.tenant, p.Get("SnapshotId"))
		if err != nil {
			return err
		}
		if old != nil {
			g.discard(old.Segments()...)
		}
		return g.ec2Return(q, "DeleteSnapshotResponse")
	case "DescribeSnapshots":
		return g.describeSnapshots(q, p)
	case "CreateImage":
		img, err := g.EC2.CreateImage(q.ctx, ec2meta.CreateImageRequest{
			Tenant: q.tenant, Instance: p.Get("InstanceId"), Name: p.Get("Name"), Description: p.Get("Description"),
			NoReboot: p.Get("NoReboot") == "true", Tags: emptyNil(p.tagSpecs("image")),
		})
		if err != nil {
			return err
		}
		return g.ec2Reply(q, "CreateImageResponse", struct {
			XMLName xml.Name `xml:"x"`
			ID      string   `xml:"imageId"`
		}{ID: img.ID})
	case "CreateVpc":
		return g.createVpc(q, p)
	case "DescribeVpcs":
		return g.describeVpcs(q, p)
	case "DeleteVpc":
		if err := g.EC2.DeleteVPC(q.ctx, q.tenant, p.Get("VpcId")); err != nil {
			return err
		}
		return g.ec2Return(q, "DeleteVpcResponse")
	case "CreateSubnet":
		return g.createSubnet(q, p)
	case "DescribeSubnets":
		return g.describeSubnets(q, p)
	case "DeleteSubnet":
		if err := g.EC2.DeleteSubnet(q.ctx, q.tenant, p.Get("SubnetId")); err != nil {
			return err
		}
		return g.ec2Return(q, "DeleteSubnetResponse")
	case "CreateSecurityGroup":
		return g.createSecurityGroup(q, p)
	case "DescribeSecurityGroups":
		return g.describeSecurityGroups(q, p)
	case "DeleteSecurityGroup":
		return g.deleteSecurityGroup(q, p)
	case "AuthorizeSecurityGroupIngress":
		return g.groupRules(q, p, false, false, "AuthorizeSecurityGroupIngressResponse")
	case "AuthorizeSecurityGroupEgress":
		return g.groupRules(q, p, true, false, "AuthorizeSecurityGroupEgressResponse")
	case "RevokeSecurityGroupIngress":
		return g.groupRules(q, p, false, true, "RevokeSecurityGroupIngressResponse")
	case "RevokeSecurityGroupEgress":
		return g.groupRules(q, p, true, true, "RevokeSecurityGroupEgressResponse")
	case "AllocateAddress":
		return g.allocateAddress(q, p)
	case "AssociateAddress":
		return g.associateAddress(q, p)
	case "DisassociateAddress":
		return g.disassociateAddress(q, p)
	case "ReleaseAddress":
		return g.releaseAddress(q, p)
	case "DescribeAddresses":
		return g.describeAddresses(q, p)
	case "CreateRouteTable":
		return g.createRouteTable(q, p)
	case "DeleteRouteTable":
		return g.deleteRouteTable(q, p)
	case "DescribeRouteTables":
		return g.describeRouteTables(q, p)
	case "CreateRoute":
		return g.setRoute(q, p, "CreateRouteResponse")
	case "ReplaceRoute":
		return g.setRoute(q, p, "ReplaceRouteResponse")
	case "DeleteRoute":
		return g.setRoute(q, p, "DeleteRouteResponse")
	case "AssociateRouteTable":
		return g.associateRouteTable(q, p)
	case "DisassociateRouteTable":
		return g.disassociateRouteTable(q, p)
	case "CreateNatGateway":
		return g.createNatGateway(q, p)
	case "DeleteNatGateway":
		return g.deleteNatGateway(q, p)
	case "DescribeNatGateways":
		return g.describeNatGateways(q, p)
	case "DescribeInternetGateways":
		return g.describeInternetGateways(q, p)
	case "GetConsoleOutput":
		c, err := g.EC2.Console(q.ctx, q.tenant, p.Get("InstanceId"))
		if err != nil {
			return err
		}
		return g.ec2Reply(q, "GetConsoleOutputResponse", struct {
			XMLName   xml.Name `xml:"x"`
			ID        string   `xml:"instanceId"`
			Timestamp string   `xml:"timestamp"`
			Output    string   `xml:"output,omitempty"`
		}{ID: c.InstanceID, Timestamp: c.Timestamp.UTC().Format(time.RFC3339), Output: base64.StdEncoding.EncodeToString(c.Output)})
	case "":
		return ec2Err("MissingAction", "no Action given")
	default:
		return ec2Err("InvalidAction", "the action %s is not supported", p.Get("Action"))
	}
}

// ec2Reply writes an EC2 response: the body's fields inside an element
// named name, with the request ID first.
func (g *Gateway) ec2Reply(q *request, name string, body any) error {
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	fmt.Fprintf(&buf, "<%s xmlns=%q><requestId>%s</requestId>", name, ec2NS, q.id)
	if body != nil {
		b, err := xml.Marshal(body)
		if err != nil {
			return err
		}
		// body is a struct marshalled as <x>...</x>; keep its children.
		inner := b[bytes.IndexByte(b, '>')+1 : bytes.LastIndexByte(b, '<')]
		buf.Write(inner)
	}
	fmt.Fprintf(&buf, "</%s>", name)
	q.w.Header().Set("Content-Type", "text/xml;charset=UTF-8")
	q.w.WriteHeader(http.StatusOK)
	_, err := q.w.Write(buf.Bytes())
	return err
}

func (g *Gateway) ec2Return(q *request, name string) error {
	return g.ec2Reply(q, name, struct {
		XMLName xml.Name `xml:"x"`
		Return  bool     `xml:"return"`
	}{Return: true})
}

func (g *Gateway) ec2Fail(q *request, e *Error) {
	type errXML struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	writeXML(q.w, e.Status, struct {
		XMLName   xml.Name `xml:"Response"`
		Errors    []errXML `xml:"Errors>Error"`
		RequestID string   `xml:"RequestID"`
	}{Errors: []errXML{{e.Code, e.Message}}, RequestID: q.id})
}

// ownerID is a stable 12-digit account number for a tenant.
func ownerID(tenant string) string { return ec2meta.AccountID(tenant) }

func (g *Gateway) zone() string { return g.region() + "a" }

// --- XML shapes ---

type tagXML struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

func tagSet(tags map[string]string) []tagXML {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]tagXML, 0, len(keys))
	for _, k := range keys {
		out = append(out, tagXML{k, tags[k]})
	}
	return out
}

type stateXML struct {
	Code int    `xml:"code"`
	Name string `xml:"name"`
}

type instanceXML struct {
	InstanceID     string   `xml:"instanceId"`
	ImageID        string   `xml:"imageId"`
	State          stateXML `xml:"instanceState"`
	PrivateDNSName string   `xml:"privateDnsName"`
	DNSName        string   `xml:"dnsName"`
	Reason         string   `xml:"reason"`
	KeyName        string   `xml:"keyName,omitempty"`
	LaunchIndex    int      `xml:"amiLaunchIndex"`
	InstanceType   string   `xml:"instanceType"`
	LaunchTime     string   `xml:"launchTime"`
	Placement      struct {
		AvailabilityZone string `xml:"availabilityZone"`
		GroupName        string `xml:"groupName"`
		Tenancy          string `xml:"tenancy"`
	} `xml:"placement"`
	Monitoring struct {
		State string `xml:"state"`
	} `xml:"monitoring"`
	PrivateIP          string           `xml:"privateIpAddress,omitempty"`
	PublicIP           string           `xml:"ipAddress,omitempty"`
	SubnetID           string           `xml:"subnetId,omitempty"`
	VpcID              string           `xml:"vpcId,omitempty"`
	Groups             []groupRefXML    `xml:"groupSet>item"`
	SourceDestCheck    bool             `xml:"sourceDestCheck"`
	Architecture       string           `xml:"architecture"`
	RootDeviceType     string           `xml:"rootDeviceType"`
	RootDeviceName     string           `xml:"rootDeviceName"`
	VirtualizationType string           `xml:"virtualizationType"`
	Hypervisor         string           `xml:"hypervisor"`
	ClientToken        string           `xml:"clientToken,omitempty"`
	Tags               []tagXML         `xml:"tagSet>item"`
	StateReason        *reasonXML       `xml:"stateReason,omitempty"`
	BlockDevices       []blockDeviceXML `xml:"blockDeviceMapping>item"`
	CPU                struct {
		CoreCount      int `xml:"coreCount"`
		ThreadsPerCore int `xml:"threadsPerCore"`
	} `xml:"cpuOptions"`
	Interfaces []eniXML `xml:"networkInterfaceSet>item"`
}

// eniXML is an instance's one network interface. A cluster instance's
// lists every node's address, node 0's as the primary.
type eniXML struct {
	ID         string        `xml:"networkInterfaceId"`
	SubnetID   string        `xml:"subnetId"`
	VpcID      string        `xml:"vpcId"`
	OwnerID    string        `xml:"ownerId"`
	Status     string        `xml:"status"`
	MAC        string        `xml:"macAddress"`
	PrivateIP  string        `xml:"privateIpAddress"`
	PrivateDNS string        `xml:"privateDnsName"`
	SourceDest bool          `xml:"sourceDestCheck"`
	Groups     []groupRefXML `xml:"groupSet>item"`
	Attachment struct {
		ID     string `xml:"attachmentId"`
		Index  int    `xml:"deviceIndex"`
		Status string `xml:"status"`
		Delete bool   `xml:"deleteOnTermination"`
	} `xml:"attachment"`
	Association *struct {
		PublicIP string `xml:"publicIp"`
	} `xml:"association,omitempty"`
	Addresses []struct {
		IP         string `xml:"privateIpAddress"`
		PrivateDNS string `xml:"privateDnsName"`
		Primary    bool   `xml:"primary"`
	} `xml:"privateIpAddressesSet>item"`
}

type groupRefXML struct {
	ID   string `xml:"groupId"`
	Name string `xml:"groupName"`
}

type blockDeviceXML struct {
	Device string `xml:"deviceName"`
	EBS    struct {
		VolumeID            string `xml:"volumeId"`
		Status              string `xml:"status"`
		AttachTime          string `xml:"attachTime"`
		DeleteOnTermination bool   `xml:"deleteOnTermination"`
	} `xml:"ebs"`
}

type reasonXML struct {
	Code    string `xml:"code"`
	Message string `xml:"message"`
}

func (g *Gateway) instanceXML(in ec2meta.Instance) instanceXML {
	x := instanceXML{
		InstanceID: in.ID, ImageID: in.ImageID, State: stateXML{ec2meta.StateCode(in.State), in.State},
		KeyName: in.KeyName, LaunchIndex: in.LaunchIndex, InstanceType: in.Type, LaunchTime: iso(in.Launched),
		PrivateIP: in.PrivateIP, Architecture: "x86_64", RootDeviceType: "instance-store", RootDeviceName: "/dev/vda",
		VirtualizationType: "hvm", Hypervisor: "kvm", ClientToken: in.ClientToken, Tags: tagSet(in.Tags),
		SubnetID: in.SubnetID, VpcID: in.VpcID, SourceDestCheck: true, PublicIP: in.PublicIP,
	}
	for _, id := range in.SecurityGroups {
		x.Groups = append(x.Groups, groupRefXML{ID: id})
	}
	x.Placement.AvailabilityZone, x.Placement.Tenancy = g.zone(), "default"
	x.Monitoring.State = "disabled"
	x.CPU.CoreCount, x.CPU.ThreadsPerCore = in.VCPU, 1
	if in.PrivateIP != "" {
		x.PrivateDNSName = "ip-" + strings.ReplaceAll(in.PrivateIP, ".", "-") + ".jy.internal"
	}
	if in.PrivateIP != "" && in.State != ec2meta.StateTerminated {
		suffix := strings.TrimPrefix(in.ID, "i-")
		eni := eniXML{ID: "eni-" + suffix, SubnetID: in.SubnetID, VpcID: in.VpcID, OwnerID: ownerID(in.Tenant), Status: "in-use",
			MAC: in.MAC, PrivateIP: in.PrivateIP, PrivateDNS: x.PrivateDNSName, SourceDest: true, Groups: x.Groups}
		eni.Attachment.ID, eni.Attachment.Status, eni.Attachment.Delete = "eni-attach-"+suffix, "attached", true
		if in.PublicIP != "" {
			eni.Association = &struct {
				PublicIP string `xml:"publicIp"`
			}{in.PublicIP}
		}
		ips := in.ClusterIPs
		if len(ips) == 0 {
			ips = []string{in.PrivateIP}
		}
		for i, ip := range ips {
			eni.Addresses = append(eni.Addresses, struct {
				IP         string `xml:"privateIpAddress"`
				PrivateDNS string `xml:"privateDnsName"`
				Primary    bool   `xml:"primary"`
			}{ip, "ip-" + strings.ReplaceAll(ip, ".", "-") + ".jy.internal", i == 0})
		}
		x.Interfaces = []eniXML{eni}
	}
	if in.StateReason != "" {
		code, _, _ := strings.Cut(in.StateReason, ":")
		x.StateReason = &reasonXML{Code: code, Message: in.StateReason}
		x.Reason = in.StateReason
	}
	return x
}

// --- Handlers ---

func (g *Gateway) describeRegions(q *request) error {
	type region struct {
		Name     string `xml:"regionName"`
		Endpoint string `xml:"regionEndpoint"`
		OptIn    string `xml:"optInStatus"`
	}
	return g.ec2Reply(q, "DescribeRegionsResponse", struct {
		XMLName xml.Name `xml:"x"`
		Regions []region `xml:"regionInfo>item"`
	}{Regions: []region{{g.region(), q.r.Host, "opt-in-not-required"}}})
}

func (g *Gateway) describeZones(q *request) error {
	type zone struct {
		Name   string `xml:"zoneName"`
		State  string `xml:"zoneState"`
		Region string `xml:"regionName"`
		ID     string `xml:"zoneId"`
		Type   string `xml:"zoneType"`
	}
	return g.ec2Reply(q, "DescribeAvailabilityZonesResponse", struct {
		XMLName xml.Name `xml:"x"`
		Zones   []zone   `xml:"availabilityZoneInfo>item"`
	}{Zones: []zone{{g.zone(), "available", g.region(), "jy-az1", "availability-zone"}}})
}

func (g *Gateway) describeInstanceTypes(q *request, p ec2Params) error {
	type typeXML struct {
		Name string `xml:"instanceType"`
		VCPU struct {
			Default int `xml:"defaultVCpus"`
		} `xml:"vCpuInfo"`
		Mem struct {
			MiB int `xml:"sizeInMiB"`
		} `xml:"memoryInfo"`
		Hypervisor string `xml:"hypervisor"`
		Current    bool   `xml:"currentGeneration"`
	}
	want := map[string]bool{}
	for _, t := range p.list("InstanceType") {
		want[t] = true
	}
	var out []typeXML
	for _, t := range ec2meta.InstanceTypes() {
		if len(want) > 0 && !want[t.Name] {
			continue
		}
		x := typeXML{Name: t.Name, Hypervisor: "kvm", Current: true}
		x.VCPU.Default, x.Mem.MiB = t.VCPU, t.MemMiB
		out = append(out, x)
	}
	return g.ec2Reply(q, "DescribeInstanceTypesResponse", struct {
		XMLName xml.Name  `xml:"x"`
		Types   []typeXML `xml:"instanceTypeSet>item"`
	}{Types: out})
}

func (g *Gateway) runInstances(q *request, p ec2Params) error {
	minC, _ := strconv.Atoi(p.Get("MinCount"))
	maxC, _ := strconv.Atoi(p.Get("MaxCount"))
	if minC < 1 || maxC < minC {
		return ec2Err(ec2meta.CodeInvalidParameter, "MinCount must be at least 1 and no more than MaxCount")
	}
	t := ec2meta.Instance{
		ImageID: p.Get("ImageId"), Type: p.Get("InstanceType"), KeyName: p.Get("KeyName"),
		ClientToken: p.Get("ClientToken"), Tags: p.tagSpecs("instance"),
	}
	if t.Type == "" {
		t.Type = "m5.large" // EC2's documented default is m1.small; this is the nearest we offer
	}
	if ud := p.Get("UserData"); ud != "" {
		b, err := base64.StdEncoding.DecodeString(ud)
		if err != nil {
			return ec2Err(ec2meta.CodeInvalidParameter, "UserData must be base64")
		}
		t.UserData = b
	}
	if pl, ok := t.Tags[PlacementTag]; ok {
		t.Placement = pl
	}
	for i := 1; ; i++ {
		pre := "BlockDeviceMapping." + strconv.Itoa(i)
		dev := p.Get(pre + ".DeviceName")
		if dev == "" {
			break
		}
		if sz := p.Get(pre + ".Ebs.VolumeSize"); sz != "" {
			n, err := strconv.Atoi(sz)
			if err != nil {
				return ec2Err(ec2meta.CodeInvalidParameter, "bad volume size %q", sz)
			}
			t.RootGiB = n
		}
	}
	if len(t.Tags) == 0 {
		t.Tags = nil
	}
	t.SubnetID = p.Get("SubnetId")
	t.SecurityGroups = p.list("SecurityGroupId")
	if ni := "NetworkInterface.1."; p.Get(ni+"SubnetId") != "" || p.Get(ni+"SecurityGroupId.1") != "" {
		if t.SubnetID == "" {
			t.SubnetID = p.Get(ni + "SubnetId")
		}
		t.SecurityGroups = append(t.SecurityGroups, p.list(ni+"SecurityGroupId")...)
	}
	if names := p.list("SecurityGroup"); len(names) > 0 {
		gs, err := g.EC2.Groups(q.ctx, ec2meta.GroupRequest{Tenant: q.tenant, Names: names})
		if err != nil {
			return err
		}
		for _, sg := range gs {
			t.SecurityGroups = append(t.SecurityGroups, sg.ID)
		}
	}
	// We launch MaxCount if possible; the control plane rejects a launch
	// no host can take, so MinCount is met or nothing is launched.
	resp, err := g.EC2.RunInstances(q.ctx, q.tenant, ec2meta.RunRequest{Template: t, Count: maxC})
	if err != nil {
		return err
	}
	var items []instanceXML
	for _, in := range resp.Instances {
		items = append(items, g.instanceXML(in))
	}
	return g.ec2Reply(q, "RunInstancesResponse", struct {
		XMLName       xml.Name      `xml:"x"`
		ReservationID string        `xml:"reservationId"`
		OwnerID       string        `xml:"ownerId"`
		Groups        []struct{}    `xml:"groupSet>item"`
		Instances     []instanceXML `xml:"instancesSet>item"`
	}{ReservationID: resp.Instances[0].ReservationID, OwnerID: ownerID(q.tenant), Instances: items})
}

// matchInstance applies DescribeInstances filters.
func matchInstance(in ec2meta.Instance, filters map[string][]string) bool {
	for name, vals := range filters {
		var got []string
		switch {
		case name == "instance-id":
			got = []string{in.ID}
		case name == "instance-state-name":
			got = []string{in.State}
		case name == "instance-state-code":
			got = []string{strconv.Itoa(ec2meta.StateCode(in.State))}
		case name == "image-id":
			got = []string{in.ImageID}
		case name == "instance-type":
			got = []string{in.Type}
		case name == "key-name":
			got = []string{in.KeyName}
		case name == "private-ip-address":
			got = []string{in.PrivateIP}
		case name == "ip-address":
			got = []string{in.PublicIP}
		case name == "reservation-id":
			got = []string{in.ReservationID}
		case name == "vpc-id":
			got = []string{in.VpcID}
		case name == "subnet-id":
			got = []string{in.SubnetID}
		case name == "instance.group-id", name == "group-id":
			got = in.SecurityGroups
		case name == "tag-key":
			for k := range in.Tags {
				got = append(got, k)
			}
		case strings.HasPrefix(name, "tag:"):
			if v, ok := in.Tags[name[4:]]; ok {
				got = []string{v}
			}
		default:
			continue // unknown filters match everything, as many tools expect
		}
		if !anyMatch(got, vals) {
			return false
		}
	}
	return true
}

// anyMatch reports whether any value matches any pattern ('*' and '?'
// wildcards, as EC2 filters allow).
func anyMatch(vals, patterns []string) bool {
	for _, v := range vals {
		for _, p := range patterns {
			if wildcard(p, v) {
				return true
			}
		}
	}
	return false
}

func wildcard(p, s string) bool {
	if p == "" {
		return s == ""
	}
	switch p[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if wildcard(p[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		return s != "" && wildcard(p[1:], s[1:])
	case '\\':
		if len(p) > 1 {
			p = p[1:]
		}
	}
	return s != "" && s[0] == p[0] && wildcard(p[1:], s[1:])
}

func (g *Gateway) describeInstances(q *request, p ec2Params) error {
	ins, err := g.EC2.Instances(q.ctx, q.tenant, p.list("InstanceId"))
	if err != nil {
		return err
	}
	filters := p.filters()
	vols, err := g.EC2.Volumes(q.ctx, q.tenant, nil)
	if err != nil {
		return err
	}
	groups, err := g.EC2.Groups(q.ctx, ec2meta.GroupRequest{Tenant: q.tenant})
	if err != nil {
		return err
	}
	groupName := map[string]string{}
	for _, sg := range groups {
		groupName[sg.ID] = sg.Name
	}
	type reservation struct {
		ID        string        `xml:"reservationId"`
		OwnerID   string        `xml:"ownerId"`
		Groups    []struct{}    `xml:"groupSet>item"`
		Instances []instanceXML `xml:"instancesSet>item"`
	}
	var out []reservation
	index := map[string]int{}
	for _, in := range ins {
		if !matchInstance(in, filters) {
			continue
		}
		i, ok := index[in.ReservationID]
		if !ok {
			i = len(out)
			index[in.ReservationID] = i
			out = append(out, reservation{ID: in.ReservationID, OwnerID: ownerID(q.tenant)})
		}
		x := g.instanceXML(in)
		for j := range x.Groups {
			x.Groups[j].Name = groupName[x.Groups[j].ID]
		}
		for _, v := range vols {
			if v.Instance == in.ID {
				var m blockDeviceXML
				m.Device = v.Device
				m.EBS.VolumeID, m.EBS.Status, m.EBS.AttachTime = v.ID, v.AttachState, iso(v.AttachTime)
				x.BlockDevices = append(x.BlockDevices, m)
			}
		}
		out[i].Instances = append(out[i].Instances, x)
	}
	return g.ec2Reply(q, "DescribeInstancesResponse", struct {
		XMLName      xml.Name      `xml:"x"`
		Reservations []reservation `xml:"reservationSet>item"`
	}{Reservations: out})
}

func (g *Gateway) describeInstanceStatus(q *request, p ec2Params) error {
	ins, err := g.EC2.Instances(q.ctx, q.tenant, p.list("InstanceId"))
	if err != nil {
		return err
	}
	all := p.Get("IncludeAllInstances") == "true"
	type detail struct {
		Name   string `xml:"name"`
		Status string `xml:"status"`
	}
	type status struct {
		Status  string   `xml:"status"`
		Details []detail `xml:"details>item"`
	}
	type item struct {
		ID     string   `xml:"instanceId"`
		Zone   string   `xml:"availabilityZone"`
		State  stateXML `xml:"instanceState"`
		System status   `xml:"systemStatus"`
		Inst   status   `xml:"instanceStatus"`
	}
	var out []item
	for _, in := range ins {
		if in.State != ec2meta.StateRunning && !all {
			continue
		}
		st := "not-applicable"
		if in.State == ec2meta.StateRunning {
			st = "ok"
		}
		s := status{st, []detail{{"reachability", map[bool]string{true: "passed", false: "not-applicable"}[st == "ok"]}}}
		out = append(out, item{in.ID, g.zone(), stateXML{ec2meta.StateCode(in.State), in.State}, s, s})
	}
	return g.ec2Reply(q, "DescribeInstanceStatusResponse", struct {
		XMLName xml.Name `xml:"x"`
		Items   []item   `xml:"instanceStatusSet>item"`
	}{Items: out})
}

func (g *Gateway) instanceAction(q *request, p ec2Params, action, name string) error {
	resp, err := g.EC2.InstanceAction(q.ctx, q.tenant, action, p.list("InstanceId"))
	if err != nil {
		return err
	}
	type change struct {
		ID       string   `xml:"instanceId"`
		Current  stateXML `xml:"currentState"`
		Previous stateXML `xml:"previousState"`
	}
	var out []change
	for _, c := range resp.Changes {
		out = append(out, change{c.ID, stateXML{ec2meta.StateCode(c.Current), c.Current}, stateXML{ec2meta.StateCode(c.Previous), c.Previous}})
	}
	return g.ec2Reply(q, name, struct {
		XMLName xml.Name `xml:"x"`
		Items   []change `xml:"instancesSet>item"`
	}{Items: out})
}

// --- Key pairs ---

func (g *Gateway) createKeyPair(q *request, p ec2Params) error {
	if f := p.Get("KeyFormat"); f != "" && f != "pem" {
		return ec2Err(ec2meta.CodeInvalidParameter, "only the pem key format is supported")
	}
	var priv []byte
	var pub ssh.PublicKey
	typ := p.Get("KeyType")
	switch typ {
	case "", "rsa":
		typ = "rsa"
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		priv = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		if pub, err = ssh.NewPublicKey(&k.PublicKey); err != nil {
			return err
		}
	case "ed25519":
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		block, err := ssh.MarshalPrivateKey(sk, "")
		if err != nil {
			return err
		}
		priv = pem.EncodeToMemory(block)
		if pub, err = ssh.NewPublicKey(pk); err != nil {
			return err
		}
	default:
		return ec2Err(ec2meta.CodeInvalidParameter, "KeyType must be rsa or ed25519")
	}
	k, err := g.EC2.PutKeyPair(q.ctx, q.tenant, ec2meta.KeyPair{
		Name: p.Get("KeyName"), Type: typ, Fingerprint: fingerprint(pub),
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), Tags: emptyNil(p.tagSpecs("key-pair")),
	})
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "CreateKeyPairResponse", struct {
		XMLName     xml.Name `xml:"x"`
		Name        string   `xml:"keyName"`
		Fingerprint string   `xml:"keyFingerprint"`
		Material    string   `xml:"keyMaterial"`
		ID          string   `xml:"keyPairId"`
	}{Name: k.Name, Fingerprint: k.Fingerprint, Material: string(priv), ID: k.ID})
}

func fingerprint(pub ssh.PublicKey) string {
	if pub.Type() == ssh.KeyAlgoRSA {
		return ssh.FingerprintLegacyMD5(pub)
	}
	return strings.TrimPrefix(ssh.FingerprintSHA256(pub), "SHA256:")
}

func emptyNil(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

func (g *Gateway) importKeyPair(q *request, p ec2Params) error {
	raw, err := base64.StdEncoding.DecodeString(p.Get("PublicKeyMaterial"))
	if err != nil {
		return ec2Err(ec2meta.CodeInvalidParameter, "PublicKeyMaterial must be base64")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return ec2Err("InvalidKey.Format", "the public key is not in OpenSSH format: %v", err)
	}
	typ := "rsa"
	switch pub.Type() {
	case ssh.KeyAlgoRSA:
	case ssh.KeyAlgoED25519:
		typ = "ed25519"
	default:
		return ec2Err("InvalidKey.Format", "only RSA and ED25519 keys are supported")
	}
	k, err := g.EC2.PutKeyPair(q.ctx, q.tenant, ec2meta.KeyPair{
		Name: p.Get("KeyName"), Type: typ, Fingerprint: fingerprint(pub),
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), Tags: emptyNil(p.tagSpecs("key-pair")),
	})
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "ImportKeyPairResponse", struct {
		XMLName     xml.Name `xml:"x"`
		Name        string   `xml:"keyName"`
		Fingerprint string   `xml:"keyFingerprint"`
		ID          string   `xml:"keyPairId"`
	}{Name: k.Name, Fingerprint: k.Fingerprint, ID: k.ID})
}

func (g *Gateway) describeKeyPairs(q *request, p ec2Params) error {
	keys, err := g.EC2.KeyPairs(q.ctx, q.tenant, p.list("KeyName"))
	if err != nil {
		return err
	}
	ids := map[string]bool{}
	for _, id := range p.list("KeyPairId") {
		ids[id] = true
	}
	filters := p.filters()
	type keyXML struct {
		ID          string   `xml:"keyPairId"`
		Name        string   `xml:"keyName"`
		Fingerprint string   `xml:"keyFingerprint"`
		Type        string   `xml:"keyType"`
		PublicKey   string   `xml:"publicKey,omitempty"`
		Created     string   `xml:"createTime"`
		Tags        []tagXML `xml:"tagSet>item"`
	}
	withPub := p.Get("IncludePublicKey") == "true"
	var out []keyXML
	for _, k := range keys {
		if len(ids) > 0 && !ids[k.ID] {
			continue
		}
		if v, ok := filters["key-name"]; ok && !anyMatch([]string{k.Name}, v) {
			continue
		}
		x := keyXML{ID: k.ID, Name: k.Name, Fingerprint: k.Fingerprint, Type: k.Type, Created: iso(k.Created), Tags: tagSet(k.Tags)}
		if withPub {
			x.PublicKey = k.PublicKey
		}
		out = append(out, x)
	}
	return g.ec2Reply(q, "DescribeKeyPairsResponse", struct {
		XMLName xml.Name `xml:"x"`
		Keys    []keyXML `xml:"keySet>item"`
	}{Keys: out})
}

// --- Images ---

// qcow2Magic starts every qcow2 file; anything else is taken as raw.
var qcow2Magic = []byte{'Q', 'F', 'I', 0xfb}

type sniffer struct {
	r    io.Reader
	head []byte
}

func (s *sniffer) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if need := 4 - len(s.head); need > 0 {
		s.head = append(s.head, p[:min(n, need)]...)
	}
	return n, err
}

// registerImage makes an image from an S3 object (ImageLocation =
// bucket/key) holding a qcow2 or raw disk image. The bytes are copied, so
// later changes to the object don't affect the image.
func (g *Gateway) registerImage(q *request, p ec2Params) error {
	loc := strings.TrimPrefix(p.Get("ImageLocation"), "s3://")
	bucket, key, _ := strings.Cut(loc, "/")
	if bucket == "" || key == "" {
		return ec2Err(ec2meta.CodeInvalidParameter, "ImageLocation must name an S3 object as bucket/key holding a qcow2 or raw disk image")
	}
	if a := p.Get("Architecture"); a != "" && a != "x86_64" {
		return ec2Err(ec2meta.CodeInvalidParameter, "only x86_64 images are supported")
	}
	src, err := g.Meta.Object(q.ctx, q.tenant, bucket, key)
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(g.read(q.ctx, q.tenant, src, 0, -1, pw)) }()
	sn := &sniffer{r: pr}
	seg, err := g.store(q.ctx, q.tenant, sn)
	pr.CloseWithError(errors.New("copy stopped"))
	if err != nil {
		return err
	}
	format := "raw"
	if bytes.Equal(sn.head, qcow2Magic) {
		format = "qcow2"
	}
	img, err := g.EC2.PutImage(q.ctx, q.tenant, ec2meta.Image{
		Name: p.Get("Name"), Description: p.Get("Description"), Location: bucket + "/" + key,
		Format: format, Size: seg.Size, Tags: emptyNil(p.tagSpecs("image")),
	}, s3meta.Object{ID: seg.ID, Size: seg.Size, ETag: seg.ETag, WrappedKey: seg.WrappedKey, Layout: seg.Layout})
	if err != nil {
		g.discard(seg)
		return err
	}
	return g.ec2Reply(q, "RegisterImageResponse", struct {
		XMLName xml.Name `xml:"x"`
		ID      string   `xml:"imageId"`
	}{ID: img.ID})
}

func (g *Gateway) describeImages(q *request, p ec2Params) error {
	imgs, err := g.EC2.Images(q.ctx, q.tenant, p.list("ImageId"))
	if err != nil {
		return err
	}
	owners := p.list("Owner")
	filters := p.filters()
	type imageXML struct {
		ID           string   `xml:"imageId"`
		Location     string   `xml:"imageLocation"`
		State        string   `xml:"imageState"`
		OwnerID      string   `xml:"imageOwnerId"`
		Created      string   `xml:"creationDate"`
		Public       bool     `xml:"isPublic"`
		Architecture string   `xml:"architecture"`
		Type         string   `xml:"imageType"`
		Name         string   `xml:"name"`
		Description  string   `xml:"description,omitempty"`
		RootType     string   `xml:"rootDeviceType"`
		RootName     string   `xml:"rootDeviceName"`
		Virt         string   `xml:"virtualizationType"`
		Hypervisor   string   `xml:"hypervisor"`
		Tags         []tagXML `xml:"tagSet>item"`
	}
	var out []imageXML
	for _, img := range imgs {
		owner := ownerID(img.Tenant)
		if len(owners) > 0 {
			ok := false
			for _, o := range owners {
				if (o == "self" && img.Tenant == q.tenant) || o == owner {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		if v, ok := filters["name"]; ok && !anyMatch([]string{img.Name}, v) {
			continue
		}
		if v, ok := filters["image-id"]; ok && !anyMatch([]string{img.ID}, v) {
			continue
		}
		if v, ok := filters["state"]; ok && !anyMatch([]string{img.StateName()}, v) {
			continue
		}
		out = append(out, imageXML{
			ID: img.ID, Location: img.Location, State: img.StateName(), OwnerID: owner, Created: iso(img.Created),
			Public: img.Public, Architecture: "x86_64", Type: "machine", Name: img.Name, Description: img.Description,
			RootType: "instance-store", RootName: "/dev/vda", Virt: "hvm", Hypervisor: "kvm", Tags: tagSet(img.Tags),
		})
	}
	return g.ec2Reply(q, "DescribeImagesResponse", struct {
		XMLName xml.Name   `xml:"x"`
		Images  []imageXML `xml:"imagesSet>item"`
	}{Images: out})
}

// --- Volumes and snapshots ---

type attachmentXML struct {
	VolumeID            string `xml:"volumeId"`
	InstanceID          string `xml:"instanceId"`
	Device              string `xml:"device"`
	Status              string `xml:"status"`
	AttachTime          string `xml:"attachTime"`
	DeleteOnTermination bool   `xml:"deleteOnTermination"`
}

type volumeXML struct {
	ID          string          `xml:"volumeId"`
	Size        int             `xml:"size"`
	SnapshotID  string          `xml:"snapshotId"`
	Zone        string          `xml:"availabilityZone"`
	Status      string          `xml:"status"`
	Created     string          `xml:"createTime"`
	Attachments []attachmentXML `xml:"attachmentSet>item"`
	Tags        []tagXML        `xml:"tagSet>item"`
	Type        string          `xml:"volumeType"`
	Encrypted   bool            `xml:"encrypted"`
	MultiAttach bool            `xml:"multiAttachEnabled"`
}

func (g *Gateway) volumeXML(v ec2meta.Volume) volumeXML {
	x := volumeXML{ID: v.ID, Size: v.SizeGiB, SnapshotID: v.SnapshotID, Zone: g.zone(), Status: v.State,
		Created: iso(v.Created), Tags: tagSet(v.Tags), Type: v.Type}
	if v.Instance != "" {
		x.Attachments = []attachmentXML{{v.ID, v.Instance, v.Device, v.AttachState, iso(v.AttachTime), false}}
	}
	return x
}

func (g *Gateway) createVolume(q *request, p ec2Params) error {
	v := ec2meta.Volume{SnapshotID: p.Get("SnapshotId"), Type: p.Get("VolumeType"), Tags: emptyNil(p.tagSpecs("volume"))}
	if sz := p.Get("Size"); sz != "" {
		n, err := strconv.Atoi(sz)
		if err != nil {
			return ec2Err(ec2meta.CodeInvalidParameter, "bad size %q", sz)
		}
		v.SizeGiB = n
	}
	if v.Type == "" {
		v.Type = "gp3"
	}
	out, err := g.EC2.CreateVolume(q.ctx, q.tenant, v)
	if err != nil {
		return err
	}
	x := g.volumeXML(*out)
	return g.ec2Reply(q, "CreateVolumeResponse", struct {
		XMLName xml.Name `xml:"x"`
		volumeXML
	}{volumeXML: x})
}

func (g *Gateway) attachVolume(q *request, p ec2Params) error {
	req := ec2meta.AttachRequest{Tenant: q.tenant, Volume: p.Get("VolumeId"), Instance: p.Get("InstanceId"), Device: p.Get("Device"), Force: p.Get("Force") == "true"}
	var v *ec2meta.Volume
	var err error
	name := p.Get("Action") + "Response"
	if p.Get("Action") == "AttachVolume" {
		v, err = g.EC2.AttachVolume(q.ctx, req)
	} else {
		v, err = g.EC2.DetachVolume(q.ctx, req)
	}
	if err != nil {
		return err
	}
	return g.ec2Reply(q, name, struct {
		XMLName xml.Name `xml:"x"`
		attachmentXML
	}{attachmentXML: attachmentXML{v.ID, v.Instance, v.Device, v.AttachState, iso(v.AttachTime), false}})
}

func (g *Gateway) describeVolumes(q *request, p ec2Params) error {
	vols, err := g.EC2.Volumes(q.ctx, q.tenant, p.list("VolumeId"))
	if err != nil {
		return err
	}
	filters := p.filters()
	var out []volumeXML
	for _, v := range vols {
		ok := true
		for name, vals := range filters {
			var got []string
			switch {
			case name == "volume-id":
				got = []string{v.ID}
			case name == "status":
				got = []string{v.State}
			case name == "attachment.instance-id":
				got = []string{v.Instance}
			case name == "attachment.status":
				got = []string{v.AttachState}
			case name == "snapshot-id":
				got = []string{v.SnapshotID}
			case strings.HasPrefix(name, "tag:"):
				if t, has := v.Tags[name[4:]]; has {
					got = []string{t}
				}
			default:
				continue
			}
			if !anyMatch(got, vals) {
				ok = false
			}
		}
		if ok {
			out = append(out, g.volumeXML(v))
		}
	}
	return g.ec2Reply(q, "DescribeVolumesResponse", struct {
		XMLName xml.Name    `xml:"x"`
		Volumes []volumeXML `xml:"volumeSet>item"`
	}{Volumes: out})
}

type snapshotXML struct {
	ID          string   `xml:"snapshotId"`
	VolumeID    string   `xml:"volumeId"`
	Status      string   `xml:"status"`
	StatusMsg   string   `xml:"statusMessage,omitempty"`
	StartTime   string   `xml:"startTime"`
	Progress    string   `xml:"progress"`
	OwnerID     string   `xml:"ownerId"`
	VolumeSize  int      `xml:"volumeSize"`
	Description string   `xml:"description"`
	Encrypted   bool     `xml:"encrypted"`
	Tags        []tagXML `xml:"tagSet>item"`
}

func (g *Gateway) snapshotXML(s ec2meta.Snapshot) snapshotXML {
	progress := "0%"
	if s.State == ec2meta.SnapshotCompleted {
		progress = "100%"
	}
	return snapshotXML{ID: s.ID, VolumeID: s.VolumeID, Status: s.State, StatusMsg: s.Reason, StartTime: iso(s.Created),
		Progress: progress, OwnerID: ownerID(s.Tenant), VolumeSize: s.SizeGiB, Description: s.Description, Encrypted: true, Tags: tagSet(s.Tags)}
}

func (g *Gateway) createSnapshot(q *request, p ec2Params) error {
	s, err := g.EC2.CreateSnapshot(q.ctx, q.tenant, p.Get("VolumeId"), p.Get("Description"), emptyNil(p.tagSpecs("snapshot")))
	if err != nil {
		return err
	}
	return g.ec2Reply(q, "CreateSnapshotResponse", struct {
		XMLName xml.Name `xml:"x"`
		snapshotXML
	}{snapshotXML: g.snapshotXML(*s)})
}

func (g *Gateway) describeSnapshots(q *request, p ec2Params) error {
	snaps, err := g.EC2.Snapshots(q.ctx, q.tenant, p.list("SnapshotId"))
	if err != nil {
		return err
	}
	filters := p.filters()
	var out []snapshotXML
	for _, s := range snaps {
		if v, ok := filters["volume-id"]; ok && !anyMatch([]string{s.VolumeID}, v) {
			continue
		}
		if v, ok := filters["status"]; ok && !anyMatch([]string{s.State}, v) {
			continue
		}
		out = append(out, g.snapshotXML(s))
	}
	return g.ec2Reply(q, "DescribeSnapshotsResponse", struct {
		XMLName   xml.Name      `xml:"x"`
		Snapshots []snapshotXML `xml:"snapshotSet>item"`
	}{Snapshots: out})
}
