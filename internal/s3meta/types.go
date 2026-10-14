// Package s3meta defines S3 metadata kept by the control plane: tenants,
// access keys, buckets and objects, and the request types the gateway uses.
package s3meta

import (
	"fmt"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// Tenant owns buckets. Its master key wraps every object's data key.
type Tenant struct {
	Name      string    `json:"name"`
	MasterKey []byte    `json:"master_key"` // AES-256
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
