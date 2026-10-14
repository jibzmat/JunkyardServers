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
