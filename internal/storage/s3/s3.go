// Package s3 stores images in an S3-compatible bucket (AWS S3, DigitalOcean
// Spaces, Cloudflare R2, MinIO, …). The bucket stays private: images are
// streamed through this service so expiry is always enforced.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/degenview/snapshots/internal/storage"
)

// Config describes a bucket.
type Config struct {
	Endpoint  string // https://nyc3.digitaloceanspaces.com, or host[:port]; empty = AWS
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	PathStyle bool   // bucket in the path rather than the hostname (MinIO, some proxies)
	Prefix    string // optional key prefix, e.g. "snapshots/"
}

// Validate checks the fields the user typed.
func (c Config) Validate() error {
	switch {
	case c.Bucket == "":
		return errors.New("bucket is required")
	case c.AccessKey == "" || c.SecretKey == "":
		return errors.New("access key and secret key are required")
	case strings.ContainsAny(c.Prefix, "\x00\\") || strings.HasPrefix(c.Prefix, "/") || strings.Contains(c.Prefix, ".."):
		return errors.New("prefix must be a plain relative path")
	}
	if _, _, err := splitEndpoint(c.Endpoint); err != nil {
		return err
	}
	return nil
}

// splitEndpoint turns "https://host:port" or "host" into (host, secure).
func splitEndpoint(ep string) (string, bool, error) {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return "s3.amazonaws.com", true, nil
	}
	if !strings.Contains(ep, "://") {
		ep = "https://" + ep
	}
	u, err := url.Parse(ep)
	if err != nil || u.Host == "" {
		return "", false, errors.New("endpoint is not a valid URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", false, errors.New("endpoint must be http:// or https://")
	}
	if u.Path != "" && u.Path != "/" {
		return "", false, errors.New("endpoint must not contain a path")
	}
	if u.User != nil {
		return "", false, errors.New("endpoint must not contain credentials")
	}
	return u.Host, u.Scheme == "https", nil
}

// Store is an S3 bucket store.
type Store struct {
	cl     *minio.Client
	bucket string
	prefix string
}

// New connects to the bucket. It does not contact the server.
func New(c Config) (*Store, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	host, secure, _ := splitEndpoint(c.Endpoint)
	lookup := minio.BucketLookupAuto
	if c.PathStyle {
		lookup = minio.BucketLookupPath
	}
	cl, err := minio.New(host, &minio.Options{
		Creds:        credentials.NewStaticV4(c.AccessKey, c.SecretKey, ""),
		Secure:       secure,
		Region:       c.Region,
		BucketLookup: lookup,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: %w", err)
	}
	prefix := strings.Trim(c.Prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &Store{cl: cl, bucket: c.Bucket, prefix: prefix}, nil
}

// Kind implements storage.Store.
func (s *Store) Kind() string { return storage.KindS3 }

func (s *Store) key(id string) string { return s.prefix + id + ".png" }

// Put implements storage.Store.
func (s *Store) Put(ctx context.Context, id string, r io.Reader, size int64) error {
	if err := storage.CheckID(id); err != nil {
		return err
	}
	_, err := s.cl.PutObject(ctx, s.bucket, s.key(id), r, size, minio.PutObjectOptions{
		ContentType:        "image/png",
		ContentDisposition: "inline",
		CacheControl:       "private, no-store",
	})
	if err != nil {
		return fmt.Errorf("s3: put: %w", describe(err))
	}
	return nil
}

// Open implements storage.Store.
func (s *Store) Open(ctx context.Context, id string) (io.ReadSeekCloser, error) {
	if err := storage.CheckID(id); err != nil {
		return nil, err
	}
	obj, err := s.cl.GetObject(ctx, s.bucket, s.key(id), minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("s3: get: %w", describe(err))
	}
	// GetObject is lazy; Stat surfaces "no such key" now rather than mid-response.
	if _, err := obj.Stat(); err != nil {
		obj.Close()
		if minio.ToErrorResponse(err).Code == minio.NoSuchKey {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("s3: stat: %w", describe(err))
	}
	return obj, nil
}

// Delete implements storage.Store. S3 reports success for missing keys.
func (s *Store) Delete(ctx context.Context, id string) error {
	if err := storage.CheckID(id); err != nil {
		return err
	}
	if err := s.cl.RemoveObject(ctx, s.bucket, s.key(id), minio.RemoveObjectOptions{}); err != nil {
		if minio.ToErrorResponse(err).Code == minio.NoSuchKey {
			return nil
		}
		return fmt.Errorf("s3: delete: %w", describe(err))
	}
	return nil
}

// Ping implements storage.Store.
func (s *Store) Ping(ctx context.Context) error {
	ok, err := s.cl.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("s3: %w", describe(err))
	}
	if !ok {
		return fmt.Errorf("s3: bucket %q does not exist", s.bucket)
	}
	return nil
}

// describe turns minio's error into a message safe to show an administrator.
func describe(err error) error {
	er := minio.ToErrorResponse(err)
	if er.Code == "" {
		return err
	}
	if er.Message != "" {
		return fmt.Errorf("%s: %s", er.Code, er.Message)
	}
	return errors.New(er.Code)
}
