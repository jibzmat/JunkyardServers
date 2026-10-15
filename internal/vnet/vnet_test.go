package vnet

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

func testNet() ec2meta.VPCNet {
	web := ec2meta.SecurityGroup{ID: "sg-web", Ingress: []ec2meta.Permission{
		{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"0.0.0.0/0"}},
		{Protocol: "tcp", FromPort: 8000, ToPort: 8080, Groups: []string{"sg-app"}},
		{Protocol: "icmp", FromPort: 8, ToPort: -1, CIDRs: []string{"10.0.0.0/16"}},
	}, Egress: []ec2meta.Permission{{Protocol: "-1", FromPort: -1, ToPort: -1, CIDRs: []string{"0.0.0.0/0"}}}}
	return ec2meta.VPCNet{
		VPC:    ec2meta.VPC{ID: "vpc-1", CIDR: "10.0.0.0/16", VNI: 1000},
		Groups: []ec2meta.SecurityGroup{web},
		Endpoints: []ec2meta.Endpoint{
			{Instance: "i-0000000000000000a", IP: "10.0.0.4", Host: "n1", Groups: []string{"sg-web"}},
			{Instance: "i-0000000000000000b", IP: "10.0.0.5", Host: "n2", HostIP: "100.64.0.2"},
		},
		Members: map[string][]string{"sg-app": {"10.0.0.5", "10.0.0.6"}},
	}
}

func TestRules(t *testing.T) {
	r := Rules("n1", testNet())
	for _, want := range []string{
		"-A FORWARD -i jy0000000000000 ! -s 10.0.0.4/32 -j DROP",
		"-A FORWARD -i jy0000000000000 -j JY-E-0000000000000000a",
		"-A FORWARD -o jy0000000000000 -j JY-I-0000000000000000a",
		"-A JY-I-0000000000000000a -s 0.0.0.0/0 -p tcp --dport 22 -j ACCEPT",
		"-A JY-I-0000000000000000a -s 10.0.0.5/32 -p tcp --dport 8000:8080 -j ACCEPT",
		"-A JY-I-0000000000000000a -s 10.0.0.6/32 -p tcp --dport 8000:8080 -j ACCEPT",
		"-A JY-I-0000000000000000a -s 10.0.0.0/16 -p icmp --icmp-type 8 -j ACCEPT",
		"-A JY-E-0000000000000000a -d 0.0.0.0/0 -j RETURN",
		"-A POSTROUTING -o up0 -j MASQUERADE",
	} {
		if !strings.Contains(r, want+"\n") {
			t.Errorf("rules lack %q", want)
		}
	}
	// Only this PC's instances get chains.
	if strings.Contains(r, "0000000000000000b") {
		t.Error("rules for another PC's instance")
	}
	// All egress jumps come before any ingress jump.
	if strings.Index(r, "-o jy") < strings.LastIndex(r, "-j JY-E-") {
		t.Error("an ingress check comes before an egress check")
	}

	// The kernel accepts them, where we can try.
	if os.Geteuid() != 0 {
		return
	}
	if _, err := exec.LookPath("iptables-restore"); err != nil {
		return
	}
	ns := "jy-vnet-test"
	if err := exec.Command("ip", "netns", "add", ns).Run(); err != nil {
		t.Skip("no network namespaces")
	}
	defer exec.Command("ip", "netns", "del", ns).Run()
	cmd := exec.Command("ip", "netns", "exec", ns, "iptables-restore")
	cmd.Stdin = strings.NewReader(r)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("iptables-restore: %v: %s\n%s", err, out, r)
	}
}

func TestTransitAndMAC(t *testing.T) {
	r, n := transitAddrs(0)
	if r.String() != "198.18.0.0" || n.String() != "198.18.0.1" {
		t.Fatal(r, n)
	}
	r, n = transitAddrs(300)
	if r.String() != "198.18.2.88" || n.String() != "198.18.2.89" {
		t.Fatal(r, n)
	}
	if m := vxlanMAC("100.64.1.2"); m != "02:6a:64:40:01:02" {
		t.Fatal(m)
	}
}

func TestEIPRules(t *testing.T) {
	n := testNet()
	n.EIPs = []ec2meta.ElasticIP{
		{PublicIP: "203.0.113.10", PrivateIP: "10.0.0.5", Instance: "i-0000000000000000b", Gateway: "n1", GatewayIP: "100.64.0.1"},
		{PublicIP: "203.0.113.11", PrivateIP: "10.0.0.4", Instance: "i-0000000000000000a", Gateway: "n3", GatewayIP: "100.64.0.3"},
	}
	r := Rules("n1", n)
	for _, want := range []string{
		"-A PREROUTING -i up0 -d 203.0.113.10/32 -j DNAT --to-destination 10.0.0.5",
		"-A POSTROUTING -s 10.0.0.5/32 -o up0 -j SNAT --to-source 203.0.113.10",
		"-A FORWARD -i up0 -o vx0 -d 10.0.0.5/32 -j ACCEPT",
		"-A FORWARD -i vx0 -o up0 -s 10.0.0.5/32 -j ACCEPT",
	} {
		if !strings.Contains(r, want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	// n3's address is not translated here.
	if strings.Contains(r, "203.0.113.11") {
		t.Error("translated another gateway's address")
	}
	// SNAT comes before the namespace's own masquerade.
	if strings.Index(r, "SNAT") > strings.Index(r, "MASQUERADE") {
		t.Error("SNAT after MASQUERADE")
	}
}

func TestNATRules(t *testing.T) {
	n := testNet()
	n.Egress = []ec2meta.SubnetEgress{
		{CIDR: "10.0.1.0/24", NAT: "nat-1", PublicIP: "203.0.113.11", Gateway: "n1", GatewayIP: "100.64.0.1"},
		{CIDR: "10.0.2.0/24", None: true},
	}
	n.EIPs = []ec2meta.ElasticIP{{PublicIP: "203.0.113.10", PrivateIP: "10.0.2.9", Instance: "i-0000000000000000c", Gateway: "n1", GatewayIP: "100.64.0.1"}}
	r := Rules("n1", n)
	for _, want := range []string{
		"-A POSTROUTING -s 10.0.1.0/24 -o up0 -j SNAT --to-source 203.0.113.11",
		"-A FORWARD -i vx0 -o up0 -s 10.0.1.0/24 -j ACCEPT",
		"-A FORWARD -s 10.0.2.9/32 -o up0 -j ACCEPT",
		"-A FORWARD -s 10.0.2.0/24 -o up0 -j DROP",
	} {
		if !strings.Contains(r, want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(r, "-s 10.0.1.0/24 -o up0 -j DROP") {
		t.Error("blocked the NAT gateway's own subnet on its PC")
	}
	// An elastic IP's SNAT wins over the NAT gateway's.
	if strings.Index(r, "--to-source 203.0.113.10") > strings.Index(r, "--to-source 203.0.113.11") {
		t.Error("NAT gateway SNAT before the elastic IP's")
	}
	if strings.Index(r, "-s 10.0.2.0/24 -o up0 -j DROP") > strings.Index(r, "-A FORWARD -i jy+ -j ACCEPT") {
		t.Error("drop after the final accept")
	}

	// On another PC, the NAT subnet is sent to n1 and blocked locally.
	r = Rules("n2", n)
	if !strings.Contains(r, "-A FORWARD -s 10.0.1.0/24 -o up0 -j DROP\n") || strings.Contains(r, "SNAT") {
		t.Errorf("n2 rules wrong:\n%s", r)
	}
	got := sourceRoutes("n2", n)
	want := []sourceRoute{{prefNAT, "10.0.1.0/24", "100.64.0.1"}}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("source routes on n2 = %v, want %v", got, want)
	}
	if got := sourceRoutes("n1", n); len(got) != 0 {
		t.Errorf("source routes on the gateway = %v", got)
	}
}
