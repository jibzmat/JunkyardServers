// Package s3meta defines S3 metadata kept by the control plane: tenants,
// access keys, buckets and objects, and the request types the gateway uses.
package s3meta

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/storage"
)

var bucketNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// ValidBucketName applies S3's bucket naming rules.
func ValidBucketName(name string) bool {
	return bucketNameRE.MatchString(name) && !strings.Contains(name, "..")
}

// Tenant owns buckets. Its master key wraps every object's data key.
type Tenant struct {
	Name string `json:"name"`
	// SealedKey is the AES-256 master key sealed by the cluster's
	// key-encryption key. MasterKey holds it in the clear only for tenants
	// created before key protection, until the next key rotation.
	SealedKey []byte    `json:"sealed_key,omitempty"`
	MasterKey []byte    `json:"master_key,omitempty"`
	Created   time.Time `json:"created"`
}

// AccessKey is an S3 credential. SigV4 verification needs the secret itself.
type AccessKey struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
	Tenant string `json:"tenant"`
}

// Bucket is an S3 bucket.
type Bucket struct {
	Name    string    `json:"name"`
	Tenant  string    `json:"tenant"`
	Created time.Time `json:"created"`
}

// Object is one stored object version.
type Object struct {
	Bucket      string         `json:"bucket"`
	Key         string         `json:"key"`
	ID          string         `json:"id"` // binds chunks to this object in the cipher
	Size        int64          `json:"size"`
	ETag        string         `json:"etag"`
	ContentType string         `json:"content_type,omitempty"`
	Modified    time.Time      `json:"modified"`
	WrappedKey  []byte         `json:"wrapped_key"` // data key sealed by the tenant master key
	Layout      storage.Layout `json:"layout"`
	// Metadata holds x-amz-meta-* headers (lower-case names, no prefix).
	Metadata map[string]string `json:"meta,omitempty"`
	// Parts is set for objects assembled by a multipart upload; each part
	// has its own ID, data key and layout. ID, WrappedKey and Layout above
	// are then unused.
	Parts []Segment `json:"parts,omitempty"`
}

// Segment is one separately encrypted run of an object's bytes.
type Segment struct {
	ID         string         `json:"id"`
	Size       int64          `json:"size"`
	ETag       string         `json:"etag"` // hex MD5 of the plaintext
	WrappedKey []byte         `json:"wrapped_key"`
	Layout     storage.Layout `json:"layout"`
}

// Segments returns the object's byte runs in order.
func (o *Object) Segments() []Segment {
	if len(o.Parts) > 0 {
		return o.Parts
	}
	return []Segment{{ID: o.ID, Size: o.Size, ETag: o.ETag, WrappedKey: o.WrappedKey, Layout: o.Layout}}
}

// ShardMove records a shard rebuilt onto another node by repair.
type ShardMove struct {
	Chunk int    `json:"chunk"`
	Index int    `json:"index"` // position in the k+m shard set
	Hash  string `json:"hash"`
	Node  string `json:"node"`
}

// Upload is a multipart upload in progress.
type Upload struct {
	ID          string            `json:"id"`
	Tenant      string            `json:"tenant"`
	Bucket      string            `json:"bucket"`
	Key         string            `json:"key"`
	ContentType string            `json:"content_type,omitempty"`
	Metadata    map[string]string `json:"meta,omitempty"`
	Created     time.Time         `json:"created"`
	Parts       map[int]*Part     `json:"parts,omitempty"`
}

// Part is one uploaded part.
type Part struct {
	Number   int       `json:"number"`
	Modified time.Time `json:"modified"`
	Segment
}

// CompletedPart is a part named in CompleteMultipartUpload.
type CompletedPart struct {
	Number int    `json:"number"`
	ETag   string `json:"etag"`
}

// Multipart limits, as in S3.
const (
	MinPartSize = 5 << 20
	MaxPartSize = 5 << 30
	MaxParts    = 10000
)

// UploadRequest names an upload. Bucket and key must match the upload's.
type UploadRequest struct {
	Tenant   string `json:"tenant"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	UploadID string `json:"upload_id"`
}

// CreateUploadRequest starts an upload.
type CreateUploadRequest struct {
	Tenant string `json:"tenant"`
	Upload Upload `json:"upload"`
}

// PutPartRequest records an uploaded part.
type PutPartRequest struct {
	UploadRequest
	Part Part `json:"part"`
}

// PartResponse returns the part a re-upload replaced, if any.
type PartResponse struct {
	Part *Part `json:"part,omitempty"`
}

// CompleteUploadRequest assembles the object.
type CompleteUploadRequest struct {
	UploadRequest
	Parts []CompletedPart `json:"parts"`
}

// CompleteUploadResponse returns the new object, the one it replaced, and
// uploaded parts left out of the object (their shards are to be deleted).
type CompleteUploadResponse struct {
	Object  *Object   `json:"object"`
	Old     *Object   `json:"old,omitempty"`
	Discard []Segment `json:"discard,omitempty"`
}

// UploadResponse returns an upload.
type UploadResponse struct {
	Upload *Upload `json:"upload,omitempty"`
}

// ListRequest is ListObjectsV2.
type ListRequest struct {
	Tenant     string `json:"tenant"`
	Bucket     string `json:"bucket"`
	Prefix     string `json:"prefix,omitempty"`
	Delimiter  string `json:"delimiter,omitempty"`
	StartAfter string `json:"start_after,omitempty"` // exclusive; also the continuation token
	MaxKeys    int    `json:"max_keys,omitempty"`
}

// ListResponse is a page of keys.
type ListResponse struct {
	Objects        []Object `json:"objects"`
	CommonPrefixes []string `json:"common_prefixes,omitempty"`
	Truncated      bool     `json:"truncated"`
	Next           string   `json:"next,omitempty"`
}

// BucketRequest names a bucket for a tenant.
type BucketRequest struct {
	Tenant string `json:"tenant"`
	Bucket string `json:"bucket"`
}

// ObjectRequest names an object for a tenant.
type ObjectRequest struct {
	Tenant string `json:"tenant"`
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

// PutObjectRequest records a stored object.
type PutObjectRequest struct {
	Tenant string `json:"tenant"`
	Object Object `json:"object"`
}

// ObjectResponse returns an object, or the one replaced or deleted.
type ObjectResponse struct {
	Object *Object `json:"object,omitempty"`
}

// KeyRequest wraps or unwraps a data key with a tenant's master key.
type KeyRequest struct {
	Tenant string `json:"tenant"`
	Key    []byte `json:"key"`
}

// KeyResponse carries the result.
type KeyResponse struct {
	Key []byte `json:"key"`
}

// TenantRequest creates a tenant (admin).
type TenantRequest struct {
	Name string `json:"name"`
}

// TenantResponse returns the tenant's first access key.
type TenantResponse struct {
	Tenant          string `json:"tenant"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// Error codes the control plane returns, mapped to S3 errors by the gateway.
const (
	CodeNoSuchBucket     = "NoSuchBucket"
	CodeNoSuchKey        = "NoSuchKey"
	CodeBucketExists     = "BucketAlreadyOwnedByYou"
	CodeBucketTaken      = "BucketAlreadyExists"
	CodeBucketNotEmpty   = "BucketNotEmpty"
	CodeInvalidAccessKey = "InvalidAccessKeyId"
	CodeTenantExists     = "TenantExists"
	CodeNoSuchUpload     = "NoSuchUpload"
	CodeInvalidPart      = "InvalidPart"
	CodeInvalidPartOrder = "InvalidPartOrder"
	CodeEntityTooSmall   = "EntityTooSmall"
)

// Error is a metadata error with an S3 error code.
type Error struct {
	Code string `json:"code"`
	Msg  string `json:"error"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

// Errorf builds an Error.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}
