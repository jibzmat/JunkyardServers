package ec2meta

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// VPC networking (M3). See docs/design.md.

// VPC is a tenant's private network.
type VPC struct {
	ID        string            `json:"id"`
	Tenant    string            `json:"tenant"`
	CIDR      string            `json:"cidr"`
	VNI       uint32            `json:"vni"` // VXLAN network identifier between PCs
	IsDefault bool              `json:"is_default,omitempty"`
	Created   time.Time         `json:"created"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// Subnet is a range of a VPC's addresses that instances launch into.
type Subnet struct {
	ID        string            `json:"id"`
	Tenant    string            `json:"tenant"`
	VpcID     string            `json:"vpc_id"`
	CIDR      string            `json:"cidr"`
	Zone      string            `json:"zone,omitempty"`
	IsDefault bool              `json:"is_default,omitempty"`
	Created   time.Time         `json:"created"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// SecurityGroup is a stateful firewall attached to instances.
type SecurityGroup struct {
	ID          string            `json:"id"`
	Tenant      string            `json:"tenant"`
	VpcID       string            `json:"vpc_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Ingress     []Permission      `json:"ingress,omitempty"`
	Egress      []Permission      `json:"egress,omitempty"`
	Created     time.Time         `json:"created"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// Permission allows traffic of one protocol and port range from (ingress)
// or to (egress) address ranges and members of other groups.
type Permission struct {
	Protocol string   `json:"protocol"` // "-1" (all), "tcp", "udp", "icmp"
	FromPort int      `json:"from_port"`
	ToPort   int      `json:"to_port"`
	CIDRs    []string `json:"cidrs,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// Defaults made for each tenant on first use, as on EC2.
const (
	DefaultVPCCIDR    = "172.31.0.0/16"
	DefaultSubnetCIDR = "172.31.0.0/20"
	DefaultGroupName  = "default"
)

// GuestMTU is instances' MTU: WireGuard (80) and VXLAN (50) headers come
// out of a 1500-byte path.
const GuestMTU = 1370

// Normalize checks a permission and puts it in canonical form: the
// protocol by name, ports -1 for "all", sorted sources.
func (p *Permission) Normalize() error {
	switch strings.ToLower(p.Protocol) {
	case "-1", "all", "":
		p.Protocol, p.FromPort, p.ToPort = "-1", -1, -1
	case "tcp", "6":
		p.Protocol = "tcp"
	case "udp", "17":
		p.Protocol = "udp"
	case "icmp", "1":
		p.Protocol = "icmp"
	default:
		return fmt.Errorf("protocol %q is not supported (tcp, udp, icmp or -1)", p.Protocol)
	}
	switch p.Protocol {
	case "tcp", "udp":
		if p.FromPort < 0 || p.ToPort > 65535 || p.FromPort > p.ToPort {
			return fmt.Errorf("port range %d-%d is not valid", p.FromPort, p.ToPort)
		}
	case "icmp":
		// FromPort is the ICMP type and ToPort the code; -1 means all.
		if p.FromPort < -1 || p.FromPort > 255 || p.ToPort < -1 || p.ToPort > 255 {
			return fmt.Errorf("icmp type %d code %d is not valid", p.FromPort, p.ToPort)
		}
	}
	if len(p.CIDRs) == 0 && len(p.Groups) == 0 {
		return fmt.Errorf("a rule needs a CIDR or a group")
	}
	for i, c := range p.CIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil || !pfx.Addr().Is4() {
			return fmt.Errorf("%q is not an IPv4 CIDR", c)
		}
		p.CIDRs[i] = pfx.Masked().String()
	}
	return nil
}

// Same reports whether two permissions match the same traffic.
func (p Permission) Same(q Permission) bool {
	return p.Protocol == q.Protocol && p.FromPort == q.FromPort && p.ToPort == q.ToPort
}

// UsableRange is the addresses of a subnet instances may get: EC2 reserves
// the first four (network, router, DNS, future use) and the last.
func UsableRange(cidr string) (first, last netip.Addr, err error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return first, last, err
	}
	p = p.Masked()
	first = p.Addr()
	for i := 0; i < 4; i++ {
		first = first.Next()
	}
	b := p.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n |= (1 << (32 - p.Bits())) - 1
	last = netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n - 1)})
	return first, last, nil
}

// VPCNet is what a compute host needs to run a VPC's instances: the VPC,
// where its other instances are, and the groups of the host's instances.
type VPCNet struct {
	VPC       VPC                 `json:"vpc"`
	Subnets   []Subnet            `json:"subnets"`
	Endpoints []Endpoint          `json:"endpoints"` // every placed instance of the VPC
	Groups    []SecurityGroup     `json:"groups"`    // groups of this host's instances
	Members   map[string][]string `json:"members"`   // group ID -> addresses, for groups rules name
	// EIPs are the VPC's elastic IPs in use.
	EIPs []ElasticIP `json:"eips,omitempty"`
}

// ElasticIP is a public address in use, as the PCs route it: the gateway
// PC receives traffic for PublicIP and sends it on to the instance at
// PrivateIP, whose traffic to the internet leaves through the gateway.
type ElasticIP struct {
	PublicIP  string `json:"public_ip"`
	PrivateIP string `json:"private_ip"`
	Instance  string `json:"instance"`
	Gateway   string `json:"gateway"`    // node ID
	GatewayIP string `json:"gateway_ip"` // its mesh address
}

// Endpoint is an instance's address and the PC it runs on.
type Endpoint struct {
	Instance string `json:"instance"`
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Host     string `json:"host"`
	HostIP   string `json:"host_ip"` // the PC's mesh address
	// Groups are the instance's security groups (needed for the host's own).
	Groups []string `json:"groups,omitempty"`
}

// Requests for VPCs, subnets and groups.

type VPCRequest struct {
	Tenant string            `json:"tenant"`
	CIDR   string            `json:"cidr,omitempty"`
	IDs    []string          `json:"ids,omitempty"`
	Tags   map[string]string `json:"tags,omitempty"`
}

type SubnetRequest struct {
	Tenant string            `json:"tenant"`
	VpcID  string            `json:"vpc_id,omitempty"`
	CIDR   string            `json:"cidr,omitempty"`
	Zone   string            `json:"zone,omitempty"`
	IDs    []string          `json:"ids,omitempty"`
	Tags   map[string]string `json:"tags,omitempty"`
}

type GroupRequest struct {
	Tenant      string            `json:"tenant"`
	VpcID       string            `json:"vpc_id,omitempty"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	IDs         []string          `json:"ids,omitempty"`
	Names       []string          `json:"names,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// RulesRequest authorizes or revokes a group's permissions.
type RulesRequest struct {
	Tenant      string       `json:"tenant"`
	GroupID     string       `json:"group_id"`
	Egress      bool         `json:"egress,omitempty"`
	Revoke      bool         `json:"revoke,omitempty"`
	Permissions []Permission `json:"permissions"`
}

// Error codes for VPC resources.
const (
	CodeVpcNotFound        = "InvalidVpcID.NotFound"
	CodeSubnetNotFound     = "InvalidSubnetID.NotFound"
	CodeGroupNotFound      = "InvalidGroup.NotFound"
	CodeGroupDuplicate     = "InvalidGroup.Duplicate"
	CodeDependency         = "DependencyViolation"
	CodeVpcRange           = "InvalidVpc.Range"
	CodeSubnetRange        = "InvalidSubnet.Range"
	CodeSubnetConflict     = "InvalidSubnet.Conflict"
	CodePermissionDup      = "InvalidPermission.Duplicate"
	CodePermissionNotFound = "InvalidPermission.NotFound"
	CodeNoFreeAddresses    = "InsufficientFreeAddressesInSubnet"
	CodeCannotDelete       = "CannotDelete"
	CodeAllocationNotFound = "InvalidAllocationID.NotFound"
	CodeAssocNotFound      = "InvalidAssociationID.NotFound"
	CodeAddressNotFound    = "InvalidAddress.NotFound"
	CodeAddressLimit       = "AddressLimitExceeded"
	CodeAlreadyAssociated  = "Resource.AlreadyAssociated"
	CodeAddressInUse       = "InvalidIPAddress.InUse"
)

// Elastic IPs (M5).

// PublicIP is an address in the cluster's pool: one that reaches Node, a
// PC that can take traffic for it (an extra address its provider routes
// to it, or one on its LAN it may answer for).
type PublicIP struct {
	IP   string `json:"ip"`
	Node string `json:"node"`
}

// Address is an elastic IP allocated to a tenant, and what it is
// associated with.
type Address struct {
	AllocationID string            `json:"allocation_id"`
	PublicIP     string            `json:"public_ip"`
	Tenant       string            `json:"tenant"`
	Tags         map[string]string `json:"tags,omitempty"`
	Created      time.Time         `json:"created"`

	AssociationID string `json:"association_id,omitempty"`
	Instance      string `json:"instance,omitempty"`
	PrivateIP     string `json:"private_ip,omitempty"`
}

// AddressRequest allocates, finds, associates or releases addresses.
type AddressRequest struct {
	Tenant        string   `json:"tenant"`
	AllocationIDs []string `json:"allocation_ids,omitempty"`
	PublicIPs     []string `json:"public_ips,omitempty"`
	AssociationID string   `json:"association_id,omitempty"`
	Instance      string   `json:"instance,omitempty"`
	// Reassociate moves an address already associated elsewhere.
	Reassociate bool              `json:"reassociate,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// PoolRequest changes the pool of public addresses (admin).
type PoolRequest struct {
	Node   string   `json:"node,omitempty"`
	IPs    []string `json:"ips"`
	Remove bool     `json:"remove,omitempty"`
}
