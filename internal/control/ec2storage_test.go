package control

import (
	"context"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
)

func TestVolumesSnapshotsAndImages(t *testing.T) {
	c, ami := ec2Setup(t)
	host, hc := joinCompute(t, c, true, bigHost)
	c.srv.StartCompute(ComputeOptions{})
	ctx := context.Background()

	resp, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 1, Template: ec2meta.Instance{ImageID: ami, Type: "t3.micro"}})
	if err != nil {
		t.Fatal(err)
	}
	in := resp.Instances[0].ID
	vol, err := c.srv.CreateVolume("alice", ec2meta.Volume{SizeGiB: 4})
	if err != nil {
		t.Fatal(err)
	}
	attach := ec2meta.AttachRequest{Tenant: "alice", Volume: vol.ID, Instance: in, Device: "/dev/sdf"}
	if err := c.srv.schedule(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.AttachVolume(ec2meta.AttachRequest{Tenant: "alice", Volume: vol.ID, Instance: in, Device: "/dev/sda1"}); !isCode(err, ec2meta.CodeInvalidParameter) {
		t.Fatalf("bad device accepted: %v", err)
	}
	if _, err := c.srv.AttachVolume(ec2meta.AttachRequest{Tenant: "bob", Volume: vol.ID, Instance: in, Device: "/dev/sdf"}); !isCode(err, ec2meta.CodeVolumeNotFound) {
		t.Fatalf("bob attached alice's volume: %v", err)
	}
	v, err := c.srv.AttachVolume(attach)
	if err != nil || v.Host != host || v.AttachState != ec2meta.AttachAttaching {
		t.Fatalf("attach: %+v %v", v, err)
	}
	if err := c.srv.DeleteVolume("alice", vol.ID); !isCode(err, ec2meta.CodeVolumeInUse) {
		t.Fatalf("deleted an attached volume: %v", err)
	}
	// No snapshot before the host has made the data.
	if _, err := c.srv.CreateSnapshot("alice", vol.ID, "", nil); !isCode(err, ec2meta.CodeIncorrectState) {
		t.Fatalf("snapshot of a volume with no data: %v", err)
	}
	view, err := hc.HostView(ctx)
	if err != nil || len(view.Volumes) != 1 {
		t.Fatalf("host view %+v %v", view, err)
	}
	if err := hc.ReportVolume(ctx, ec2meta.VolumeReport{ID: vol.ID, Ready: true, AttachState: ec2meta.AttachAttached}); err != nil {
		t.Fatal(err)
	}
	vs, _ := c.srv.Volumes(ec2meta.VolumeRequest{Tenant: "alice"})
	if len(vs) != 1 || !vs[0].Ready || vs[0].AttachState != ec2meta.AttachAttached || vs[0].State != ec2meta.VolumeInUse {
		t.Fatalf("volumes %+v", vs)
	}

	// A snapshot is a task for the host; its upload completes it.
	snap, err := c.srv.CreateSnapshot("alice", vol.ID, "backup", nil)
	if err != nil || snap.State != ec2meta.SnapshotPending || snap.SizeGiB != 4 {
		t.Fatalf("snapshot %+v %v", snap, err)
	}
	view, _ = hc.HostView(ctx)
	if len(view.Tasks) != 1 || view.Tasks[0].Target != snap.ID || view.Tasks[0].Volume != vol.ID {
		t.Fatalf("tasks %+v", view.Tasks)
	}
	task := view.Tasks[0]
	if _, err := c.srv.ec2Apply(opTaskDone, "", ec2Command{Host: "someone-else", Task: &task, Object: &s3meta.Object{ID: "seg-s", Size: 3}}); err == nil {
		t.Fatal("another host completed the task")
	}
	if _, err := c.srv.ec2Apply(opTaskDone, "", ec2Command{Host: host, Task: &task, Object: &s3meta.Object{ID: "seg-s", Size: 3}}); err != nil {
		t.Fatal(err)
	}
	ss, _ := c.srv.Snapshots(ec2meta.VolumeRequest{Tenant: "alice", IDs: []string{snap.ID}})
	if len(ss) != 1 || ss[0].State != ec2meta.SnapshotCompleted {
		t.Fatalf("snapshot %+v", ss)
	}
	if o, _ := c.srv.fsm.st.Objects[snapshotBucket].get(snap.ID); o == nil || o.ID != "seg-s" {
		t.Fatal("snapshot bytes not stored")
	}

	// Restore: smaller than the snapshot is refused; the restore holds the
	// snapshot until the data is made.
	if _, err := c.srv.CreateVolume("alice", ec2meta.Volume{SnapshotID: snap.ID, SizeGiB: 2}); !isCode(err, ec2meta.CodeInvalidParameter) {
		t.Fatalf("volume smaller than its snapshot: %v", err)
	}
	restored, err := c.srv.CreateVolume("alice", ec2meta.Volume{SnapshotID: snap.ID})
	if err != nil || restored.SizeGiB != 4 {
		t.Fatalf("restore %+v %v", restored, err)
	}
	if _, err := c.srv.DeleteSnapshot("alice", snap.ID); err == nil {
		t.Fatal("deleted a snapshot being restored")
	}

	// Detach waits for the host; then delete waits for the host too.
	d, err := c.srv.DetachVolume(ec2meta.AttachRequest{Tenant: "alice", Volume: vol.ID})
	if err != nil || d.AttachState != ec2meta.AttachDetaching {
		t.Fatalf("detach %+v %v", d, err)
	}
	if err := hc.ReportVolume(ctx, ec2meta.VolumeReport{ID: vol.ID, AttachState: ec2meta.AttachDetached}); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.DeleteVolume("alice", vol.ID); err != nil {
		t.Fatal(err)
	}
	vs, _ = c.srv.Volumes(ec2meta.VolumeRequest{Tenant: "alice", IDs: []string{vol.ID}})
	if len(vs) != 1 || vs[0].State != ec2meta.VolumeDeleting {
		t.Fatalf("deleting %+v", vs)
	}
	if err := hc.ReportVolume(ctx, ec2meta.VolumeReport{ID: vol.ID, Deleted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.Volumes(ec2meta.VolumeRequest{Tenant: "alice", IDs: []string{vol.ID}}); !isCode(err, ec2meta.CodeVolumeNotFound) {
		t.Fatalf("volume not gone: %v", err)
	}
	// A volume never placed on a PC is deleted at once.
	if err := c.srv.DeleteVolume("alice", restored.ID); err != nil {
		t.Fatal(err)
	}
	if obj, err := c.srv.DeleteSnapshot("alice", snap.ID); err != nil || obj == nil || obj.ID != "seg-s" {
		t.Fatalf("delete snapshot %+v %v", obj, err)
	}

	// CreateImage needs a running or stopped instance; a failed task
	// fails the image.
	if _, err := c.srv.CreateImage(ec2meta.CreateImageRequest{Tenant: "alice", Instance: in, Name: "mine"}); !isCode(err, ec2meta.CodeIncorrectState) {
		t.Fatalf("image of a pending instance: %v", err)
	}
	if err := hc.ReportInstance(ctx, ec2meta.StatusReport{ID: in, State: ec2meta.StateRunning}); err != nil {
		t.Fatal(err)
	}
	img, err := c.srv.CreateImage(ec2meta.CreateImageRequest{Tenant: "alice", Instance: in, Name: "mine"})
	if err != nil || img.State != ec2meta.ImagePending {
		t.Fatalf("create image %+v %v", img, err)
	}
	view, _ = hc.HostView(ctx)
	if len(view.Tasks) != 1 || view.Tasks[0].Kind != ec2meta.TaskImage || view.Tasks[0].Instance != in {
		t.Fatalf("tasks %+v", view.Tasks)
	}
	if err := hc.FailTask(ctx, ec2meta.TaskFailure{ID: view.Tasks[0].ID, Reason: "disk full"}); err != nil {
		t.Fatal(err)
	}
	imgs, _ := c.srv.Images(ec2meta.ImageRequest{Tenant: "alice", IDs: []string{img.ID}})
	if len(imgs) != 1 || imgs[0].State != ec2meta.ImageFailed || imgs[0].Reason != "disk full" {
		t.Fatalf("image %+v", imgs)
	}
	if _, err := c.srv.RunInstances("alice", ec2meta.RunRequest{Count: 1, Template: ec2meta.Instance{ImageID: img.ID, Type: "t3.micro"}}); err == nil {
		t.Fatal("launched from a failed image")
	}
}
