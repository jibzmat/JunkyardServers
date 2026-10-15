package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
)

// EC2 calls, made by gateways.

// RunInstances launches instances.
func (c *Client) RunInstances(ctx context.Context, tenant string, req ec2meta.RunRequest) (*ec2meta.RunResponse, error) {
	in := struct {
		Tenant string `json:"tenant"`
		ec2meta.RunRequest
	}{tenant, req}
	var out ec2meta.RunResponse
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/instances/run", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Instances lists a tenant's instances, or the ones named.
func (c *Client) Instances(ctx context.Context, tenant string, ids []string) ([]ec2meta.Instance, error) {
	var out ec2meta.InstancesResponse
	err := c.call(ctx, http.MethodPost, "/v1/ec2/instances/list", ec2meta.InstancesRequest{Tenant: tenant, IDs: ids}, &out)
	return out.Instances, err
}

// InstanceAction stops, starts, reboots or terminates instances.
func (c *Client) InstanceAction(ctx context.Context, tenant, action string, ids []string) (*ec2meta.ChangeResponse, error) {
	var out ec2meta.ChangeResponse
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/instances/"+action, ec2meta.InstancesRequest{Tenant: tenant, IDs: ids}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutKeyPair registers a key pair and returns it as stored.
func (c *Client) PutKeyPair(ctx context.Context, tenant string, k ec2meta.KeyPair) (*ec2meta.KeyPair, error) {
	k.Tenant = tenant
	var out ec2meta.KeyPair
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/key-pairs/put", k, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteKeyPair removes a key pair.
func (c *Client) DeleteKeyPair(ctx context.Context, tenant, name string) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/key-pairs/delete", ec2meta.KeyPairRequest{Tenant: tenant, Names: []string{name}}, &out)
}

// KeyPairs lists a tenant's key pairs, or the ones named.
func (c *Client) KeyPairs(ctx context.Context, tenant string, names []string) ([]ec2meta.KeyPair, error) {
	var out []ec2meta.KeyPair
	err := c.call(ctx, http.MethodPost, "/v1/ec2/key-pairs/list", ec2meta.KeyPairRequest{Tenant: tenant, Names: names}, &out)
	return out, err
}

// PutImage records an image whose bytes are already stored as obj.
func (c *Client) PutImage(ctx context.Context, tenant string, img ec2meta.Image, obj s3meta.Object) (*ec2meta.Image, error) {
	img.Tenant = tenant
	var out ec2meta.Image
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/images/put", putImageRequest{Image: img, Object: obj}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteImage removes an image and returns the object whose shards the
// caller should delete.
func (c *Client) DeleteImage(ctx context.Context, tenant, id string) (*s3meta.Object, error) {
	var out s3meta.ObjectResponse
	err := c.call(ctx, http.MethodPost, "/v1/ec2/images/delete", ec2meta.ImageRequest{Tenant: tenant, IDs: []string{id}}, &out)
	return out.Object, err
}

// Images lists the images a tenant can see, or the ones named.
func (c *Client) Images(ctx context.Context, tenant string, ids []string) ([]ec2meta.Image, error) {
	var out []ec2meta.Image
	err := c.call(ctx, http.MethodPost, "/v1/ec2/images/list", ec2meta.ImageRequest{Tenant: tenant, IDs: ids}, &out)
	return out, err
}

// Tags adds or removes tags.
func (c *Client) Tags(ctx context.Context, req ec2meta.TagsRequest) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/tags", req, &out)
}

// Calls made by compute hosts.

// HostView returns the instances assigned to this host.
func (c *Client) HostView(ctx context.Context) (*ec2meta.HostView, error) {
	var out ec2meta.HostView
	if err := c.call(ctx, http.MethodGet, "/v1/ec2/host", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReportInstance tells the control plane an instance's actual state.
func (c *Client) ReportInstance(ctx context.Context, r ec2meta.StatusReport) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/host/report", r, &out)
}

// FetchImage streams an image's bytes to w and returns its format.
func (c *Client) FetchImage(ctx context.Context, id string, w io.Writer) (format string, err error) {
	hc := *c.http
	hc.Timeout = 0 // images are large; ctx bounds the download
	var errs []error
	cw := &countingWriter{w: w}
	for _, a := range c.Addrs() {
		format, err := fetchImage(ctx, &hc, "https://"+a+"/v1/ec2/host/images/"+id, cw)
		if err == nil {
			return format, nil
		}
		var he *httpErr
		if cw.n > 0 || (errors.As(err, &he) && he.code != http.StatusServiceUnavailable) {
			return "", err // part written, or a real refusal: don't retry
		}
		errs = append(errs, err)
	}
	return "", errors.Join(errs...)
}

func fetchImage(ctx context.Context, hc *http.Client, url string, w io.Writer) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", &httpErr{code: resp.StatusCode, msg: string(b)}
	}
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return "", err
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return "", fmt.Errorf("control: image %d of %d bytes", n, resp.ContentLength)
	}
	return resp.Header.Get("X-Image-Format"), nil
}

// Volumes, snapshots and CreateImage (gateways).

// CreateVolume makes a volume.
func (c *Client) CreateVolume(ctx context.Context, tenant string, v ec2meta.Volume) (*ec2meta.Volume, error) {
	v.Tenant = tenant
	var out ec2meta.Volume
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/volumes/create", v, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteVolume deletes a volume.
func (c *Client) DeleteVolume(ctx context.Context, tenant, id string) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/volumes/delete", ec2meta.VolumeRequest{Tenant: tenant, IDs: []string{id}}, &out)
}

// AttachVolume attaches a volume to an instance.
func (c *Client) AttachVolume(ctx context.Context, req ec2meta.AttachRequest) (*ec2meta.Volume, error) {
	var out ec2meta.Volume
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/volumes/attach", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DetachVolume detaches a volume.
func (c *Client) DetachVolume(ctx context.Context, req ec2meta.AttachRequest) (*ec2meta.Volume, error) {
	var out ec2meta.Volume
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/volumes/detach", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Volumes lists a tenant's volumes, or the ones named.
func (c *Client) Volumes(ctx context.Context, tenant string, ids []string) ([]ec2meta.Volume, error) {
	var out []ec2meta.Volume
	err := c.call(ctx, http.MethodPost, "/v1/ec2/volumes/list", ec2meta.VolumeRequest{Tenant: tenant, IDs: ids}, &out)
	return out, err
}

// CreateSnapshot starts a snapshot of a volume.
func (c *Client) CreateSnapshot(ctx context.Context, tenant, volume, description string, tags map[string]string) (*ec2meta.Snapshot, error) {
	var out ec2meta.Snapshot
	req := createSnapshotRequest{Tenant: tenant, Volume: volume, Description: description, Tags: tags}
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/snapshots/create", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSnapshot deletes a snapshot and returns the object whose shards
// the caller should delete.
func (c *Client) DeleteSnapshot(ctx context.Context, tenant, id string) (*s3meta.Object, error) {
	var out s3meta.ObjectResponse
	err := c.call(ctx, http.MethodPost, "/v1/ec2/snapshots/delete", ec2meta.VolumeRequest{Tenant: tenant, IDs: []string{id}}, &out)
	return out.Object, err
}

// Snapshots lists a tenant's snapshots, or the ones named.
func (c *Client) Snapshots(ctx context.Context, tenant string, ids []string) ([]ec2meta.Snapshot, error) {
	var out []ec2meta.Snapshot
	err := c.call(ctx, http.MethodPost, "/v1/ec2/snapshots/list", ec2meta.VolumeRequest{Tenant: tenant, IDs: ids}, &out)
	return out, err
}

// CreateImage starts making an image from an instance.
func (c *Client) CreateImage(ctx context.Context, req ec2meta.CreateImageRequest) (*ec2meta.Image, error) {
	var out ec2meta.Image
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/images/create", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Host calls for volumes and tasks.

// ReportVolume tells the control plane a volume's progress.
func (c *Client) ReportVolume(ctx context.Context, r ec2meta.VolumeReport) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/host/volume-report", r, &out)
}

// ReportReplica tells the control plane how far an instance's disk copies are.
func (c *Client) ReportReplica(ctx context.Context, r ec2meta.ReplicaReport) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/host/replica-report", r, &out)
}

// ReportMigration tells the control plane how a live migration ended.
func (c *Client) ReportMigration(ctx context.Context, r ec2meta.MigrationReport) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/host/migrated", r, &out)
}

// Migrate live-migrates an instance, or drains or undrains a PC (admin).
func (c *Client) Migrate(ctx context.Context, req ec2meta.MigrateRequest) (*ec2meta.Instance, error) {
	var out *ec2meta.Instance
	err := c.call(ctx, http.MethodPost, "/v1/admin/migrate", req, &out)
	return out, err
}

// Reinstate lifts a storage node's suspension (admin).
func (c *Client) Reinstate(ctx context.Context, node string) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/admin/reinstate", map[string]string{"node": node}, &out)
}

// FailTask reports a task the host couldn't do.
func (c *Client) FailTask(ctx context.Context, f ec2meta.TaskFailure) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/host/task-failed", f, &out)
}

// UploadTask streams a task's disk to the control plane. open is called
// for each attempt (a redirect to the leader resends the body).
func (c *Client) UploadTask(ctx context.Context, id string, open func() (io.ReadCloser, int64, error)) error {
	hc := *c.http
	hc.Timeout = 0
	var errs []error
	for _, a := range c.Addrs() {
		body, size, err := open()
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://"+a+"/v1/ec2/host/tasks/"+id, body)
		if err != nil {
			body.Close()
			return err
		}
		req.ContentLength = size
		req.GetBody = func() (io.ReadCloser, error) {
			b, _, err := open()
			return b, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		he := &httpErr{code: resp.StatusCode, msg: string(msg)}
		if resp.StatusCode != http.StatusServiceUnavailable {
			return he
		}
		errs = append(errs, he)
	}
	return errors.Join(errs...)
}

// FetchSnapshot streams a snapshot's bytes (qcow2) to w.
func (c *Client) FetchSnapshot(ctx context.Context, id string, w io.Writer) error {
	hc := *c.http
	hc.Timeout = 0
	var errs []error
	cw := &countingWriter{w: w}
	for _, a := range c.Addrs() {
		_, err := fetchImage(ctx, &hc, "https://"+a+"/v1/ec2/host/snapshots/"+id, cw)
		if err == nil {
			return nil
		}
		var he *httpErr
		if cw.n > 0 || (errors.As(err, &he) && he.code != http.StatusServiceUnavailable) {
			return err
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Console returns an instance's latest console output.
func (c *Client) Console(ctx context.Context, tenant, id string) (*ec2meta.ConsoleOutput, error) {
	var out ec2meta.ConsoleOutput
	if err := c.call(ctx, http.MethodPost, "/v1/ec2/console", ec2meta.InstancesRequest{Tenant: tenant, IDs: []string{id}}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendConsole sends an instance's console output from its host.
func (c *Client) SendConsole(ctx context.Context, out ec2meta.ConsoleOutput) error {
	var resp struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/host/console", out, &resp)
}

// VPCs, subnets and security groups.

func (c *Client) CreateVPC(ctx context.Context, req ec2meta.VPCRequest) (*ec2meta.VPC, error) {
	var out ec2meta.VPC
	return &out, c.call(ctx, http.MethodPost, "/v1/ec2/vpcs/create", req, &out)
}

func (c *Client) DeleteVPC(ctx context.Context, tenant, id string) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/vpcs/delete", ec2meta.VPCRequest{Tenant: tenant, IDs: []string{id}}, &out)
}

func (c *Client) VPCs(ctx context.Context, req ec2meta.VPCRequest) ([]ec2meta.VPC, error) {
	var out []ec2meta.VPC
	return out, c.call(ctx, http.MethodPost, "/v1/ec2/vpcs/list", req, &out)
}

func (c *Client) CreateSubnet(ctx context.Context, req ec2meta.SubnetRequest) (*ec2meta.Subnet, error) {
	var out ec2meta.Subnet
	return &out, c.call(ctx, http.MethodPost, "/v1/ec2/subnets/create", req, &out)
}

func (c *Client) DeleteSubnet(ctx context.Context, tenant, id string) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/subnets/delete", ec2meta.SubnetRequest{Tenant: tenant, IDs: []string{id}}, &out)
}

func (c *Client) Subnets(ctx context.Context, req ec2meta.SubnetRequest) ([]ec2meta.Subnet, error) {
	var out []ec2meta.Subnet
	return out, c.call(ctx, http.MethodPost, "/v1/ec2/subnets/list", req, &out)
}

func (c *Client) CreateGroup(ctx context.Context, req ec2meta.GroupRequest) (*ec2meta.SecurityGroup, error) {
	var out ec2meta.SecurityGroup
	return &out, c.call(ctx, http.MethodPost, "/v1/ec2/groups/create", req, &out)
}

func (c *Client) DeleteGroup(ctx context.Context, tenant, id string) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/groups/delete", ec2meta.GroupRequest{Tenant: tenant, IDs: []string{id}}, &out)
}

func (c *Client) Groups(ctx context.Context, req ec2meta.GroupRequest) ([]ec2meta.SecurityGroup, error) {
	var out []ec2meta.SecurityGroup
	return out, c.call(ctx, http.MethodPost, "/v1/ec2/groups/list", req, &out)
}

func (c *Client) GroupRules(ctx context.Context, req ec2meta.RulesRequest) (*ec2meta.SecurityGroup, error) {
	var out ec2meta.SecurityGroup
	return &out, c.call(ctx, http.MethodPost, "/v1/ec2/groups/rules", req, &out)
}

// --- Elastic IPs ---

func (c *Client) AllocateAddress(ctx context.Context, req ec2meta.AddressRequest) (*ec2meta.Address, error) {
	var out ec2meta.Address
	return &out, c.call(ctx, http.MethodPost, "/v1/ec2/addresses/allocate", req, &out)
}

func (c *Client) ReleaseAddress(ctx context.Context, req ec2meta.AddressRequest) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/addresses/release", req, &out)
}

func (c *Client) AssociateAddress(ctx context.Context, req ec2meta.AddressRequest) (*ec2meta.Address, error) {
	var out ec2meta.Address
	return &out, c.call(ctx, http.MethodPost, "/v1/ec2/addresses/associate", req, &out)
}

func (c *Client) DisassociateAddress(ctx context.Context, req ec2meta.AddressRequest) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/addresses/disassociate", req, &out)
}

func (c *Client) Addresses(ctx context.Context, req ec2meta.AddressRequest) ([]ec2meta.Address, error) {
	var out []ec2meta.Address
	return out, c.call(ctx, http.MethodPost, "/v1/ec2/addresses/list", req, &out)
}

// Pool adds public addresses to, or removes them from, the pool (admin).
func (c *Client) Pool(ctx context.Context, req ec2meta.PoolRequest) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/admin/public-ips", req, &out)
}

// PublicIPs lists the pool (admin).
func (c *Client) PublicIPs(ctx context.Context) ([]PoolEntry, error) {
	var out []PoolEntry
	return out, c.call(ctx, http.MethodGet, "/v1/admin/public-ips", nil, &out)
}

// --- Route tables and NAT gateways ---

func (c *Client) CreateRouteTable(ctx context.Context, req ec2meta.RouteRequest) (*ec2meta.RouteTable, error) {
	var out ec2meta.RouteTable
	return &out, c.call(ctx, http.MethodPost, "/v1/ec2/route-tables/create", req, &out)
}

func (c *Client) DeleteRouteTable(ctx context.Context, req ec2meta.RouteRequest) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/route-tables/delete", req, &out)
}

// SetRoute creates, replaces or (with no Route) deletes a default route.
func (c *Client) SetRoute(ctx context.Context, req ec2meta.RouteRequest) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/route-tables/route", req, &out)
}

func (c *Client) AssociateRouteTable(ctx context.Context, req ec2meta.RouteRequest) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.call(ctx, http.MethodPost, "/v1/ec2/route-tables/associate", req, &out)
	return out.ID, err
}

func (c *Client) DisassociateRouteTable(ctx context.Context, req ec2meta.RouteRequest) error {
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/ec2/route-tables/disassociate", req, &out)
}

func (c *Client) RouteTables(ctx context.Context, req ec2meta.RouteRequest) ([]ec2meta.RouteTable, error) {
	var out []ec2meta.RouteTable
	return out, c.call(ctx, http.MethodPost, "/v1/ec2/route-tables/list", req, &out)
}

func (c *Client) CreateNatGateway(ctx context.Context, req ec2meta.RouteRequest) (*ec2meta.NatGateway, error) {
	var out ec2meta.NatGateway
	return &out, c.call(ctx, http.MethodPost, "/v1/ec2/nat-gateways/create", req, &out)
}

func (c *Client) DeleteNatGateway(ctx context.Context, req ec2meta.RouteRequest) (*ec2meta.NatGateway, error) {
	var out ec2meta.NatGateway
	return &out, c.call(ctx, http.MethodPost, "/v1/ec2/nat-gateways/delete", req, &out)
}

func (c *Client) NatGateways(ctx context.Context, req ec2meta.RouteRequest) ([]ec2meta.NatGateway, error) {
	var out []ec2meta.NatGateway
	return out, c.call(ctx, http.MethodPost, "/v1/ec2/nat-gateways/list", req, &out)
}
