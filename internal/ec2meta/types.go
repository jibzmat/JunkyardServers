// Package ec2meta holds the EC2 records kept in the control plane's state
// (instances, key pairs, images) and the requests that carry them between
// the gateway, the control plane and compute hosts.
package ec2meta

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
)

// Placement says which hosts may run an instance. See docs/design.md.
const (
	PlacementConfidential = "confidential" // SEV-SNP/TDX hosts only
	PlacementPrivate      = "private"      // owner-trusted or confidential hosts (default)
	PlacementAny          = "any"          // any compute host, including strangers'
)

// ValidPlacement reports whether p names a placement.
func ValidPlacement(p string) bool {
	return p == PlacementConfidential || p == PlacementPrivate || p == PlacementAny
}

// Instance states, as EC2 names them.
const (
	StatePending      = "pending"
	StateRunning      = "running"
	StateShuttingDown = "shutting-down"
	StateTerminated   = "terminated"
	StateStopping     = "stopping"
	StateStopped      = "stopped"
)

// StateCode is EC2's numeric code for a state.
func StateCode(s string) int {
	switch s {
	case StatePending:
		return 0
	case StateRunning:
		return 16
	case StateShuttingDown:
		return 32
	case StateTerminated:
		return 48
	case StateStopping:
		return 64
	case StateStopped:
		return 80
	}
	return 0
}

// InstanceType is a size an instance can be launched with.
type InstanceType struct {
	Name   string `json:"name"`
	VCPU   int    `json:"vcpu"`
	MemMiB int    `json:"mem_mib"`
}

var instanceTypes = map[string]InstanceType{}

func init() {
	for _, t := range []InstanceType{
		{"t3.nano", 2, 512}, {"t3.micro", 2, 1024}, {"t3.small", 2, 2048},
		{"t3.medium", 2, 4096}, {"t3.large", 2, 8192}, {"t3.xlarge", 4, 16384},
		{"t3.2xlarge", 8, 32768},
		{"m5.large", 2, 8192}, {"m5.xlarge", 4, 16384}, {"m5.2xlarge", 8, 32768},
		{"c5.large", 2, 4096}, {"c5.xlarge", 4, 8192}, {"c5.2xlarge", 8, 16384},
		{"r5.large", 2, 16384}, {"r5.xlarge", 4, 32768},
	} {
		instanceTypes[t.Name] = t
	}
}

// LookupType returns the named instance type.
func LookupType(name string) (InstanceType, bool) {
	t, ok := instanceTypes[name]
	return t, ok
}

// InstanceTypes lists every type, by name.
func InstanceTypes() []InstanceType {
	out := make([]InstanceType, 0, len(instanceTypes))
	for _, t := range instanceTypes {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DefaultRootGiB is the root disk size when the launch doesn't name one.
const DefaultRootGiB = 8

// MaxUserData is EC2's limit on user data (after base64 decoding).
const MaxUserData = 16 << 10

// Instance is one virtual machine.
type Instance struct {
	ID        string            `json:"id"`
	Tenant    string            `json:"tenant"`
	ImageID   string            `json:"image_id"`
	Type      string            `json:"type"`
	VCPU      int               `json:"vcpu"`
	MemMiB    int               `json:"mem_mib"`
	RootGiB   int               `json:"root_gib"`
	KeyName   string            `json:"key_name,omitempty"`
	PublicKey string            `json:"public_key,omitempty"` // the key pair's, copied at launch
	UserData  []byte            `json:"user_data,omitempty"`
	Placement string            `json:"placement"`
	Tags      map[string]string `json:"tags,omitempty"`
	// ReservationID groups the instances of one RunInstances call.
	ReservationID string    `json:"reservation_id"`
	LaunchIndex   int       `json:"launch_index"`
	ClientToken   string    `json:"client_token,omitempty"`
	Launched      time.Time `json:"launched"`

	State       string    `json:"state"`
	StateReason string    `json:"state_reason,omitempty"`
	Changed     time.Time `json:"changed"` // when State last changed

	// Set by the scheduler.
	Host      string `json:"host,omitempty"` // node ID
	PrivateIP string `json:"private_ip,omitempty"`
	MAC       string `json:"mac,omitempty"`

	// RebootSeq is bumped by RebootInstances; the host reboots the VM when
	// it sees a value it hasn't acted on.
	RebootSeq int `json:"reboot_seq,omitempty"`
}

// KeyPair is an SSH public key registered under a name.
type KeyPair struct {
	Tenant      string            `json:"tenant"`
	Name        string            `json:"name"`
	ID          string            `json:"id"`
	Type        string            `json:"type"` // rsa or ed25519
	Fingerprint string            `json:"fingerprint"`
	PublicKey   string            `json:"public_key"` // authorized_keys format
	Created     time.Time         `json:"created"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// Image is a disk image instances boot from. Its bytes are a private copy
// of the S3 object it was registered from, so deleting that object doesn't
// break the image.
type Image struct {
	ID          string            `json:"id"`
	Tenant      string            `json:"tenant"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Location    string            `json:"location"` // bucket/key it was copied from
	Format      string            `json:"format"`   // qcow2 or raw
	Size        int64             `json:"size"`
	Public      bool              `json:"public,omitempty"`
	Created     time.Time         `json:"created"`
	Tags        map[string]string `json:"tags,omitempty"`
	// State is pending while CreateImage copies an instance's disk, then
	// available (or failed). Empty means available.
	State  string `json:"state,omitempty"`
	Reason string `json:"reason,omitempty"`
	// SourceInstance is the instance CreateImage made it from.
	SourceInstance string `json:"source_instance,omitempty"`
}

// Image states.
const (
	ImagePending   = "pending"
	ImageAvailable = "available"
	ImageFailed    = "failed"
)

// Available reports whether instances can be launched from the image.
func (i Image) Available() bool { return i.State == "" || i.State == ImageAvailable }

// StateName is the image's state as EC2 names it.
func (i Image) StateName() string {
	if i.State == "" {
		return ImageAvailable
	}
	return i.State
}

// Volume is a block device an instance can attach (EBS's API). Its data
// lives on one compute PC, chosen when it is first attached; snapshots
// copy it into the cluster's encrypted, erasure-coded storage, and a new
// volume can be made from a snapshot on any PC.
type Volume struct {
	ID         string            `json:"id"`
	Tenant     string            `json:"tenant"`
	SizeGiB    int               `json:"size_gib"`
	SnapshotID string            `json:"snapshot_id,omitempty"`
	Type       string            `json:"type"`
	State      string            `json:"state"` // available, in-use, deleting
	Created    time.Time         `json:"created"`
	Tags       map[string]string `json:"tags,omitempty"`

	// Host is the PC holding the data; empty until first attached.
	Host string `json:"host,omitempty"`
	// Ready is set once the host has created the data (blank, or restored
	// from the snapshot).
	Ready bool `json:"ready,omitempty"`

	Instance    string    `json:"instance,omitempty"`
	Device      string    `json:"device,omitempty"`
	AttachState string    `json:"attach_state,omitempty"` // attaching, attached, detaching
	AttachTime  time.Time `json:"attach_time,omitempty"`
}

// Volume and attachment states.
const (
	VolumeAvailable = "available"
	VolumeInUse     = "in-use"
	VolumeDeleting  = "deleting"
	VolumeDeleted   = "deleted"

	AttachAttaching = "attaching"
	AttachAttached  = "attached"
	AttachDetaching = "detaching"
	AttachDetached  = "detached"
)

// Snapshot is a point-in-time copy of a volume.
type Snapshot struct {
	ID          string            `json:"id"`
	Tenant      string            `json:"tenant"`
	VolumeID    string            `json:"volume_id"`
	SizeGiB     int               `json:"size_gib"`
	Description string            `json:"description,omitempty"`
	State       string            `json:"state"` // pending, completed, error
	Reason      string            `json:"reason,omitempty"`
	Created     time.Time         `json:"created"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// Snapshot states.
const (
	SnapshotPending   = "pending"
	SnapshotCompleted = "completed"
	SnapshotError     = "error"
)

// Task is work a compute host does for the control plane: copying an
// instance's root disk into an image, or a volume into a snapshot. The
// host streams the bytes to the control plane, which stores them.
type Task struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"` // image or snapshot
	Tenant   string    `json:"tenant"`
	Host     string    `json:"host"`
	Instance string    `json:"instance,omitempty"` // image: whose root disk
	Volume   string    `json:"volume,omitempty"`   // snapshot: which volume
	Target   string    `json:"target"`             // the ami- or snap- being made
	NoReboot bool      `json:"no_reboot,omitempty"`
	Created  time.Time `json:"created"`
}

// Task kinds.
const (
	TaskImage    = "image"
	TaskSnapshot = "snapshot"
)

// VolumeReport is a host reporting a volume's progress.
type VolumeReport struct {
	ID          string `json:"id"`
	Ready       bool   `json:"ready,omitempty"`
	AttachState string `json:"attach_state,omitempty"` // attached or detached
	Deleted     bool   `json:"deleted,omitempty"`
}

// TaskFailure is a host reporting a task it couldn't do.
type TaskFailure struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// AccountID is a stable 12-digit account number for a tenant, shown as
// owner IDs and in instance identity documents.
func AccountID(tenant string) string {
	h := sha256.Sum256([]byte("jy-owner:" + tenant))
	return fmt.Sprintf("%012d", binary.BigEndian.Uint64(h[:8])%1_000_000_000_000)
}

// ConsoleOutput is the tail of an instance's serial console.
type ConsoleOutput struct {
	InstanceID string    `json:"instance_id"`
	Output     []byte    `json:"output"`
	Timestamp  time.Time `json:"timestamp"`
}

// MaxConsole is how much console output is kept, as on EC2.
const MaxConsole = 64 << 10

// HostSubnetBits is the size of the subnet each compute host's instances
// get addresses from.
const HostSubnetBits = 24

// HostView is what a compute host fetches: its subnet, instances,
// volumes and tasks.
type HostView struct {
	Subnet    string     `json:"subnet"` // e.g. 10.128.3.0/24; empty until first scheduled
	Instances []Instance `json:"instances"`
	Volumes   []Volume   `json:"volumes,omitempty"`
	Tasks     []Task     `json:"tasks,omitempty"`
}

// StatusReport is a host reporting an instance's actual state.
type StatusReport struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// Requests between the gateway and the control plane.

// RunRequest launches Count copies of Template.
type RunRequest struct {
	Template Instance `json:"template"`
	Count    int      `json:"count"`
}

// RunResponse lists the instances launched.
type RunResponse struct {
	Instances []Instance `json:"instances"`
}

// InstancesRequest names a tenant's instances; no IDs means all.
type InstancesRequest struct {
	Tenant string   `json:"tenant"`
	IDs    []string `json:"ids,omitempty"`
}

// InstancesResponse returns instances, sorted by launch time.
type InstancesResponse struct {
	Instances []Instance `json:"instances"`
}

// ChangeResponse reports state changes made by stop, start or terminate.
type ChangeResponse struct {
	Changes []StateChange `json:"changes"`
}

// StateChange is one instance's previous and current state.
type StateChange struct {
	ID       string `json:"id"`
	Previous string `json:"previous"`
	Current  string `json:"current"`
}

// KeyPairRequest names a key pair, or all of a tenant's when Name is empty.
type KeyPairRequest struct {
	Tenant string   `json:"tenant"`
	Names  []string `json:"names,omitempty"`
}

// ImageRequest names images visible to a tenant; no IDs means all.
type ImageRequest struct {
	Tenant string   `json:"tenant"`
	IDs    []string `json:"ids,omitempty"`
}

// TagsRequest adds (or with Delete, removes) tags on resources.
type TagsRequest struct {
	Tenant    string            `json:"tenant"`
	Resources []string          `json:"resources"`
	Tags      map[string]string `json:"tags"`
	Delete    bool              `json:"delete,omitempty"`
}

// VolumeRequest names volumes; no IDs means all of the tenant's.
type VolumeRequest struct {
	Tenant string   `json:"tenant"`
	IDs    []string `json:"ids,omitempty"`
}

// AttachRequest attaches or detaches a volume.
type AttachRequest struct {
	Tenant   string `json:"tenant"`
	Volume   string `json:"volume"`
	Instance string `json:"instance,omitempty"`
	Device   string `json:"device,omitempty"`
	Force    bool   `json:"force,omitempty"`
}

// CreateImageRequest makes an image from an instance's root disk.
type CreateImageRequest struct {
	Tenant      string            `json:"tenant"`
	Instance    string            `json:"instance"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	NoReboot    bool              `json:"no_reboot,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// Error codes, as EC2 names them.
const (
	CodeInvalidInstanceID = "InvalidInstanceID.NotFound"
	CodeInvalidAMIID      = "InvalidAMIID.NotFound"
	CodeKeyPairNotFound   = "InvalidKeyPair.NotFound"
	CodeKeyPairDuplicate  = "InvalidKeyPair.Duplicate"
	CodeInvalidParameter  = "InvalidParameterValue"
	CodeIncorrectState    = "IncorrectInstanceState"
	CodeInsufficientCap   = "InsufficientInstanceCapacity"
	CodeUnsupported       = "Unsupported"
	CodeVolumeNotFound    = "InvalidVolume.NotFound"
	CodeVolumeInUse       = "VolumeInUse"
	CodeSnapshotNotFound  = "InvalidSnapshot.NotFound"
)
