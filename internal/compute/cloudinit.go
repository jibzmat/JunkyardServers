package compute

import (
	"fmt"
	"strings"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// Cloud-init NoCloud seed: meta-data, user-data and network-config files
// on a volume labelled "cidata". Every cloud image reads it.

// DNS servers given to instances.
var DNS = []string{"1.1.1.1", "8.8.8.8"}

func hostname(in ec2meta.Instance) string {
	return "ip-" + strings.ReplaceAll(in.PrivateIP, ".", "-")
}

func metaData(in ec2meta.Instance) string {
	var b strings.Builder
	fmt.Fprintf(&b, "instance-id: %s\nlocal-hostname: %s\n", in.ID, hostname(in))
	if in.PublicKey != "" {
		fmt.Fprintf(&b, "public-keys:\n  - %q\n", in.PublicKey)
	}
	return b.String()
}

// userData is the instance's own user data, or a cloud-config that only
// installs the key pair when it has none.
func userData(in ec2meta.Instance) string {
	if len(in.UserData) > 0 {
		return string(in.UserData)
	}
	var b strings.Builder
	b.WriteString("#cloud-config\n")
	if in.PublicKey != "" {
		fmt.Fprintf(&b, "ssh_authorized_keys:\n  - %q\n", in.PublicKey)
	}
	return b.String()
}

// networkConfig gives the instance its address statically: the host's
// bridge (.1 of the subnet) is the gateway.
func networkConfig(in ec2meta.Instance, gateway string, bits int) string {
	var dns []string
	for _, d := range DNS {
		dns = append(dns, d)
	}
	return fmt.Sprintf(`version: 2
ethernets:
  eth0:
    match:
      macaddress: "%s"
    set-name: eth0
    addresses: [%s/%d]
    routes:
      - to: default
        via: %s
    nameservers:
      addresses: [%s]
`, in.MAC, in.PrivateIP, bits, gateway, strings.Join(dns, ", "))
}
