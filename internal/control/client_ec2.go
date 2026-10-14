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
	for _, a := range c.Addrs() {
		format, err := fetchImage(ctx, &hc, "https://"+a+"/v1/ec2/host/images/"+id, w)
		if err == nil {
			return format, nil
		}
		var he *httpErr
		if errors.As(err, &he) && he.code != http.StatusServiceUnavailable {
			return "", err
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
