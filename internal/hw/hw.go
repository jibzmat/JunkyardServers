// Package hw reports the hardware a node offers to the cluster. The control
// plane uses it to pick roles and trust tiers; confidential-compute flags are
// only claims until attestation lands (milestone M2).
package hw

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Info describes a node's hardware.
type Info struct {
	Arch     string `json:"arch"`
	Cores    int    `json:"cores"`
	MemBytes uint64 `json:"mem_bytes"`
	KVM      bool   `json:"kvm"`     // /dev/kvm is present
	AESNI    bool   `json:"aes_ni"`  // hardware AES
	SEVSNP   bool   `json:"sev_snp"` // AMD SEV-SNP enabled in the kernel
	TDX      bool   `json:"tdx"`     // Intel TDX host support
}

// Detect inspects the local machine. Anything it cannot read is left zero.
func Detect() Info {
	info := Info{Arch: runtime.GOARCH, Cores: runtime.NumCPU()}
	info.MemBytes = memTotal("/proc/meminfo")
	flags := cpuFlags("/proc/cpuinfo")
	info.AESNI = flags["aes"]
	info.TDX = flags["tdx_host_platform"] || fileIs("/sys/module/kvm_intel/parameters/tdx", "Y")
	info.SEVSNP = flags["sev_snp"] && fileIs("/sys/module/kvm_amd/parameters/sev_snp", "Y")
	_, err := os.Stat("/dev/kvm")
	info.KVM = err == nil
	return info
}

// Confidential reports whether the node claims hardware memory encryption
// for guests.
func (i Info) Confidential() bool { return i.SEVSNP || i.TDX }

func memTotal(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0
			}
			return kb * 1024
		}
	}
	return 0
}

func cpuFlags(path string) map[string]bool {
	flags := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return flags
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := s.Text()
		if !strings.HasPrefix(line, "flags") {
			continue
		}
		_, list, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		for _, fl := range strings.Fields(list) {
			flags[fl] = true
		}
		break // every core lists the same flags
	}
	return flags
}

func fileIs(path, want string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	v := strings.TrimSpace(string(b))
	return v == want || (want == "Y" && v == "1")
}
