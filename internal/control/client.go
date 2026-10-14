package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/token"
)

// Join sends req to the control plane named in tok. The new node has no CA
// yet, so it pins the CA by the fingerprint in the token and only accepts a
// control-plane certificate signed by that CA.
func Join(ctx context.Context, tok token.Token, req cluster.JoinRequest) (*cluster.JoinResponse, error) {
	req.TokenID = tok.ID
	req.TokenSecret = tok.Secret
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Standard verification needs a root we don't have yet; the pinned
		// check below replaces it and is strictly narrower.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinned(cs.PeerCertificates, tok.CAFingerprint)
		},
	}
	var resp cluster.JoinResponse
	if err := do(ctx, newHTTPClient(cfg), http.MethodPost, "https://"+tok.Control+"/v1/join", req, &resp); err != nil {
		return nil, err
	}
	caCert, err := pki.ParseCertPEM(resp.CAPEM)
	if err != nil {
		return nil, err
	}
	if pki.Fingerprint(caCert.Raw) != tok.CAFingerprint {
		return nil, errors.New("control: returned CA does not match token")
	}
	return &resp, nil
}

func verifyPinned(chain []*x509.Certificate, fingerprint string) error {
	if len(chain) < 2 {
		return errors.New("control: server did not send its CA")
	}
	var ca *x509.Certificate
	for _, c := range chain[1:] {
		if pki.Fingerprint(c.Raw) == fingerprint {
			ca = c
		}
	}
	if ca == nil {
		return errors.New("control: server CA does not match the join token")
	}
	leaf, err := pki.VerifyAgainst(ca, chain[0].Raw)
	if err != nil {
		return fmt.Errorf("control: server certificate: %w", err)
	}
	if pki.KindOf(leaf) != pki.KindControl {
		return errors.New("control: server is not a control plane")
	}
	return nil
}

// Client talks to the control plane with a cluster certificate. It tries each
// control address in turn, and follows redirects to the leader.
type Client struct {
	addrs []string
	http  *http.Client
}

// NewClient builds a client that presents cert and trusts only caCert.
func NewClient(addrs []string, cert tls.Certificate, caCert *x509.Certificate) *Client {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}
	return &Client{addrs: addrs, http: newHTTPClient(cfg)}
}

// Members lists the cluster's nodes.
func (c *Client) Members(ctx context.Context) ([]cluster.Member, error) {
	var out []cluster.Member
	err := c.call(ctx, http.MethodGet, "/v1/members", nil, &out)
	return out, err
}

// Controls lists the control nodes.
func (c *Client) Controls(ctx context.Context) ([]ControlInfo, error) {
	var out []ControlInfo
	err := c.call(ctx, http.MethodGet, "/v1/controls", nil, &out)
	return out, err
}

// IssueToken asks for a join token (admin certificate required).
func (c *Client) IssueToken(ctx context.Context, req cluster.TokenRequest) (string, error) {
	var out cluster.TokenResponse
	err := c.call(ctx, http.MethodPost, "/v1/tokens", req, &out)
	return out.Token, err
}

// EnrollControl asks to become a control node (node certificate required).
func (c *Client) EnrollControl(ctx context.Context, req cluster.ControlEnrollRequest) (*cluster.ControlEnrollResponse, error) {
	var out cluster.ControlEnrollResponse
	if err := c.call(ctx, http.MethodPost, "/v1/controls/enroll", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActivateControl asks the leader to add the caller to the Raft group
// (control certificate required).
func (c *Client) ActivateControl(ctx context.Context) error {
	var out map[string]string
	return c.call(ctx, http.MethodPost, "/v1/controls/activate", struct{}{}, &out)
}

// RemoveControl removes a control node (admin certificate required).
func (c *Client) RemoveControl(ctx context.Context, id string) error {
	var out map[string]string
	return c.call(ctx, http.MethodDelete, "/v1/controls/"+id, nil, &out)
}

// call tries each address until one answers. A refusal from a reachable
// control node (4xx) is returned at once; only transport failures and 503s
// move on to the next address.
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	if len(c.addrs) == 0 {
		return errors.New("control: no control plane address")
	}
	var errs []error
	for _, a := range c.addrs {
		err := do(ctx, c.http, method, "https://"+a+path, in, out)
		if err == nil {
			return nil
		}
		var he *httpErr
		if errors.As(err, &he) && he.code != http.StatusServiceUnavailable {
			return err
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func newHTTPClient(cfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true},
	}
}

type httpErr struct {
	code int
	msg  string
}

func (e *httpErr) Error() string {
	if e.msg != "" {
		return fmt.Sprintf("control: %s (%d)", e.msg, e.code)
	}
	return fmt.Sprintf("control: HTTP %d", e.code)
}

func do(ctx context.Context, hc *http.Client, method, url string, in, out any) error {
	var body []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = b
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return &httpErr{code: resp.StatusCode, msg: e.Error}
	}
	return json.Unmarshal(data, out)
}
