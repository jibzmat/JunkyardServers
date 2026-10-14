package control

import (
	"context"
	"strings"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

func TestConsoleOutput(t *testing.T) {
	c, ami := ec2Setup(t)
	host, hc := joinCompute(t, c, true, bigHost)
	_, other := joinCompute(t, c, true, bigHost)
	c.srv.compute = ComputeOptions{}
	resp, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 1, Template: ec2meta.Instance{ImageID: ami, Type: "t3.micro"}})
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Instances[0].ID
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	in, _ := c.srv.Instances(ec2meta.InstancesRequest{Tenant: "alice", IDs: []string{id}})
	runs, sends := hc, other
	if in[0].Host != host {
		runs, sends = other, hc
	}
	ctx := context.Background()
	if err := sends.SendConsole(ctx, ec2meta.ConsoleOutput{InstanceID: id, Output: []byte("forged")}); err == nil {
		t.Fatal("a host sent console output for an instance it doesn't run")
	}
	big := strings.Repeat("x", ec2meta.MaxConsole) + "login:"
	if err := runs.SendConsole(ctx, ec2meta.ConsoleOutput{InstanceID: id, Output: []byte(big)}); err != nil {
		t.Fatal(err)
	}
	out, err := c.srv.Console("alice", id)
	if err != nil || len(out.Output) != ec2meta.MaxConsole || !strings.HasSuffix(string(out.Output), "login:") {
		t.Fatalf("console: %d bytes, %v", len(out.Output), err)
	}
	if _, err := c.srv.Console("bob", id); !isCode(err, ec2meta.CodeInvalidInstanceID) {
		t.Fatalf("bob read alice's console: %v", err)
	}
}
