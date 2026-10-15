package compute

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// The instance metadata service. Guests reach it at 169.254.169.254:80,
// which is on the loopback of their VPC's namespace; jyd listens there
// through a socket opened inside the namespace, so a caller is known by its
// VPC and source address (which the PC stops instances forging). It
// answers from the host's own copy of its instances, so it works while the
// control plane is unreachable.

// MetadataIP is the address guests ask, as on EC2.
const MetadataIP = "169.254.169.254"

const (
	tokenHeader    = "X-Aws-Ec2-Metadata-Token"
	tokenTTLHeader = "X-Aws-Ec2-Metadata-Token-Ttl-Seconds"
	maxTokenTTL    = 6 * time.Hour
)

// metadataServer serves one host's instances, one listener per VPC.
type metadataServer struct {
	h       *Host
	key     []byte
	region  string
	servers map[string]*http.Server // by VPC
}

func newMetadataServer(h *Host) (*metadataServer, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	region := h.Region
	if region == "" {
		region = "us-east-1"
	}
	return &metadataServer{h: h, key: key, region: region, servers: map[string]*http.Server{}}, nil
}

// syncMetadata listens in each VPC namespace that has none yet, and stops
// listening in the ones gone.
func (h *Host) syncMetadata(ctx context.Context, nets []ec2meta.VPCNet) {
	h.mu.Lock()
	if h.meta == nil {
		m, err := newMetadataServer(h)
		if err != nil {
			h.mu.Unlock()
			h.logf("compute: metadata service: %v", err)
			return
		}
		h.meta = m
		go func() {
			<-ctx.Done()
			h.mu.Lock()
			defer h.mu.Unlock()
			for _, s := range m.servers {
				s.Close()
			}
		}()
	}
	m := h.meta
	want := map[string]bool{}
	var start []string
	for _, n := range nets {
		want[n.VPC.ID] = true
		if m.servers[n.VPC.ID] == nil {
			start = append(start, n.VPC.ID)
		}
	}
	for vpc, s := range m.servers {
		if !want[vpc] {
			s.Close()
			delete(m.servers, vpc)
		}
	}
	h.mu.Unlock()
	for _, vpc := range start {
		l, err := h.Net.Listen(vpc, net.JoinHostPort(MetadataIP, "80"))
		if err != nil {
			h.logf("compute: metadata service for %s: %v", vpc, err)
			continue
		}
		s := &http.Server{Handler: m.handler(vpc), ReadHeaderTimeout: 5 * time.Second}
		h.mu.Lock()
		m.servers[vpc] = s
		h.mu.Unlock()
		go s.Serve(l)
	}
}

// instance returns the instance a request comes from.
func (m *metadataServer) instance(vpc string, r *http.Request) (ec2meta.Instance, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ec2meta.Instance{}, false
	}
	m.h.mu.Lock()
	defer m.h.mu.Unlock()
	in, ok := m.h.byIP[vpc+"/"+host]
	return in, ok
}

func (m *metadataServer) handler(vpc string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.serve(vpc, w, r) })
}

func (m *metadataServer) serve(vpc string, w http.ResponseWriter, r *http.Request) {
	in, ok := m.instance(vpc, r)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	// IMDSv2 refuses proxied requests, so a proxy on the instance can't be
	// used to read its credentials from outside.
	if r.Header.Get("X-Forwarded-For") != "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPut && strings.TrimSuffix(r.URL.Path, "/") == "/latest/api/token" {
		ttl, err := strconv.Atoi(r.Header.Get(tokenTTLHeader))
		if err != nil || ttl < 1 || time.Duration(ttl)*time.Second > maxTokenTTL {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		w.Header().Set(tokenTTLHeader, strconv.Itoa(ttl))
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, m.token(in, time.Now().Add(time.Duration(ttl)*time.Second)))
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, PUT")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// IMDSv1 (no token) is allowed; a token that is sent must be valid.
	if t := r.Header.Get(tokenHeader); t != "" && !m.validToken(in, t) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	body, ok := m.lookup(in, r.URL.Path)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/document") {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "text/plain")
	}
	fmt.Fprint(w, body)
}

// token is expiry || HMAC(key, instance, IP, expiry), so tokens die with
// the instance's address and with this process.
func (m *metadataServer) token(in ec2meta.Instance, exp time.Time) string {
	b := binary.BigEndian.AppendUint64(nil, uint64(exp.Unix()))
	return base64.RawURLEncoding.EncodeToString(append(b, m.mac(in, b)...))
}

func (m *metadataServer) mac(in ec2meta.Instance, exp []byte) []byte {
	h := hmac.New(sha256.New, m.key)
	fmt.Fprintf(h, "%s\x00%s\x00", in.ID, in.PrivateIP)
	h.Write(exp)
	return h.Sum(nil)
}

func (m *metadataServer) validToken(in ec2meta.Instance, t string) bool {
	b, err := base64.RawURLEncoding.DecodeString(t)
	if err != nil || len(b) != 8+sha256.Size {
		return false
	}
	if time.Now().Unix() > int64(binary.BigEndian.Uint64(b[:8])) {
		return false
	}
	return hmac.Equal(b[8:], m.mac(in, b[:8]))
}

// lookup answers a metadata path: a value, or a directory listing.
func (m *metadataServer) lookup(in ec2meta.Instance, path string) (string, bool) {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return "latest", true
	}
	version, rest, _ := strings.Cut(path, "/")
	if version != "latest" && !isDateVersion(version) {
		return "", false
	}
	tree := m.tree(in)
	if rest == "" {
		rest = "/"
	}
	if v, ok := tree[rest]; ok && !strings.HasSuffix(rest, "/") {
		return v, true
	}
	dir := strings.TrimSuffix(rest, "/") + "/"
	if dir == "/" {
		dir = ""
	}
	if v, ok := tree[dir]; ok {
		return v, true
	}
	seen := map[string]bool{}
	var names []string
	for k := range tree {
		if !strings.HasPrefix(k, dir) {
			continue
		}
		name, deeper, _ := strings.Cut(k[len(dir):], "/")
		if deeper != "" || strings.HasSuffix(k, "/") {
			name += "/"
		}
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", false
	}
	sort.Strings(names)
	return strings.Join(names, "\n"), true
}

func isDateVersion(v string) bool {
	_, err := time.Parse("2006-01-02", v)
	return err == nil
}

// tree is every leaf of an instance's metadata, by path under a version.
func (m *metadataServer) tree(in ec2meta.Instance) map[string]string {
	zone := m.region + "a"
	t := map[string]string{
		"meta-data/ami-id":                                               in.ImageID,
		"meta-data/ami-launch-index":                                     strconv.Itoa(in.LaunchIndex),
		"meta-data/block-device-mapping/ami":                             "/dev/sda1",
		"meta-data/block-device-mapping/root":                            "/dev/sda1",
		"meta-data/hostname":                                             hostname(in),
		"meta-data/instance-id":                                          in.ID,
		"meta-data/instance-life-cycle":                                  "on-demand",
		"meta-data/instance-type":                                        in.Type,
		"meta-data/local-hostname":                                       hostname(in),
		"meta-data/local-ipv4":                                           in.PrivateIP,
		"meta-data/mac":                                                  in.MAC,
		"meta-data/placement/availability-zone":                          zone,
		"meta-data/placement/availability-zone-id":                       "jy-" + zone,
		"meta-data/placement/region":                                     m.region,
		"meta-data/reservation-id":                                       in.ReservationID,
		"meta-data/services/domain":                                      "amazonaws.com",
		"meta-data/services/partition":                                   "aws",
		"meta-data/network/interfaces/macs/" + in.MAC + "/device-number": "0",
		"meta-data/network/interfaces/macs/" + in.MAC + "/local-ipv4s":   in.PrivateIP,
		"meta-data/network/interfaces/macs/" + in.MAC + "/mac":           in.MAC,
	}
	if in.PublicKey != "" {
		t["meta-data/public-keys/"] = "0=" + in.KeyName // listed as EC2 lists it
		t["meta-data/public-keys/0/openssh-key"] = in.PublicKey + "\n"
	}
	if in.PublicIP != "" {
		t["meta-data/public-ipv4"] = in.PublicIP
		t["meta-data/network/interfaces/macs/"+in.MAC+"/public-ipv4s"] = in.PublicIP
	}
	if len(in.UserData) > 0 {
		t["user-data"] = string(in.UserData)
	}
	for k, v := range in.Tags {
		if k != "" && !strings.ContainsAny(k, "/\n") {
			t["meta-data/tags/instance/"+k] = v
		}
	}
	doc, _ := json.MarshalIndent(map[string]any{
		"accountId":        ec2meta.AccountID(in.Tenant),
		"architecture":     "x86_64",
		"availabilityZone": zone,
		"imageId":          in.ImageID,
		"instanceId":       in.ID,
		"instanceType":     in.Type,
		"pendingTime":      in.Launched.UTC().Format(time.RFC3339),
		"privateIp":        in.PrivateIP,
		"region":           m.region,
		"version":          "2017-09-30",
	}, "", "  ")
	t["dynamic/instance-identity/document"] = string(doc)
	return t
}
