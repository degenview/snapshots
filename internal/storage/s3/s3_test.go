package s3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"

	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/storage"
)

var ctx = context.Background()

func fake(t *testing.T, prefix string) (*Store, *s3mem.Backend) {
	t.Helper()
	be := s3mem.New()
	if err := be.CreateBucket("snaps"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gofakes3.New(be).Server())
	t.Cleanup(srv.Close)
	s, err := New(Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "snaps", AccessKey: "k", SecretKey: "s", PathStyle: true, Prefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	return s, be
}

func TestRoundTrip(t *testing.T) {
	s, _ := fake(t, "")
	id, _ := ids.ImageID()
	data := bytes.Repeat([]byte("png!"), 1000)
	if err := s.Put(ctx, id, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	f, err := s.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if n, err := f.Seek(0, io.SeekEnd); err != nil || n != int64(len(data)) {
		t.Fatalf("size %d %v", n, err)
	}
	f.Seek(0, io.SeekStart)
	got, _ := io.ReadAll(f)
	if !bytes.Equal(got, data) {
		t.Fatal("bytes differ")
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestPrefixAppliesToKeys(t *testing.T) {
	s, be := fake(t, "snapshots/")
	id, _ := ids.ImageID()
	if err := s.Put(ctx, id, strings.NewReader("x"), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := be.HeadObject("snaps", "snapshots/"+id+".png"); err != nil {
		t.Fatalf("object not under prefix: %v", err)
	}
}

func TestRejectsHostileIDs(t *testing.T) {
	s, _ := fake(t, "p")
	for _, id := range []string{"", "../x", "a/b", "abcdefghij/../x", strings.Repeat("a", 11)} {
		if _, err := s.Open(ctx, id); !errors.Is(err, storage.ErrInvalidID) {
			t.Errorf("Open(%q) = %v", id, err)
		}
		if err := s.Put(ctx, id, strings.NewReader("x"), 1); !errors.Is(err, storage.ErrInvalidID) {
			t.Errorf("Put(%q) = %v", id, err)
		}
		if err := s.Delete(ctx, id); !errors.Is(err, storage.ErrInvalidID) {
			t.Errorf("Delete(%q) = %v", id, err)
		}
	}
}

func TestPingAndProbe(t *testing.T) {
	s, _ := fake(t, "")
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := storage.Probe(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s.Kind() != storage.KindS3 {
		t.Fatal()
	}
}

func TestMissingBucketIsReported(t *testing.T) {
	s, _ := fake(t, "")
	s.bucket = "nope"
	if err := s.Ping(ctx); err == nil {
		t.Fatal("missing bucket not detected")
	}
	id, _ := ids.ImageID()
	err := s.Put(ctx, id, strings.NewReader("x"), 1)
	if err == nil || !strings.Contains(err.Error(), "NoSuchBucket") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnreachableEndpoint(t *testing.T) {
	s, err := New(Config{Endpoint: "http://127.0.0.1:1", Bucket: "b", AccessKey: "k", SecretKey: "s", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	c, cancel := context.WithTimeout(ctx, 3e9)
	defer cancel()
	if err := s.Ping(c); err == nil {
		t.Fatal("expected error")
	}
}

func TestConfigValidate(t *testing.T) {
	ok := Config{Bucket: "b", AccessKey: "k", SecretKey: "s"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"no bucket":      func(c *Config) { c.Bucket = "" },
		"no access":      func(c *Config) { c.AccessKey = "" },
		"no secret":      func(c *Config) { c.SecretKey = "" },
		"prefix dotdot":  func(c *Config) { c.Prefix = "a/../b" },
		"prefix abs":     func(c *Config) { c.Prefix = "/abs" },
		"prefix nul":     func(c *Config) { c.Prefix = "a\x00" },
		"endpoint path":  func(c *Config) { c.Endpoint = "https://h.com/path" },
		"endpoint creds": func(c *Config) { c.Endpoint = "https://u:p@h.com" },
		"endpoint ftp":   func(c *Config) { c.Endpoint = "ftp://h.com" },
		"endpoint junk":  func(c *Config) { c.Endpoint = "https://" },
	} {
		c := ok
		mod(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for ep, want := range map[string]struct {
		host   string
		secure bool
	}{
		"":                                    {"s3.amazonaws.com", true},
		"nyc3.digitaloceanspaces.com":         {"nyc3.digitaloceanspaces.com", true},
		"https://nyc3.digitaloceanspaces.com": {"nyc3.digitaloceanspaces.com", true},
		"http://minio:9000/":                  {"minio:9000", false},
	} {
		h, sec, err := splitEndpoint(ep)
		if err != nil || h != want.host || sec != want.secure {
			t.Errorf("%q → %q %v %v", ep, h, sec, err)
		}
	}
}

func TestPlaintext(t *testing.T) {
	for ep, want := range map[string]bool{
		"":                            false, // AWS, https
		"nyc3.digitaloceanspaces.com": false,
		"https://s3.example.com":      false,
		"http://127.0.0.1:9000":       false,
		"http://localhost:9000":       false,
		"http://[::1]:9000":           false,
		"http://minio.internal:9000":  true,
		"http://10.0.0.5:9000":        true,
		"http://s3.example.com":       true,
	} {
		if got := (Config{Endpoint: ep}).Plaintext(); got != want {
			t.Errorf("%q: Plaintext() = %v, want %v", ep, got, want)
		}
	}
}
