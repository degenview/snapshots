package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	t.Setenv("LISTEN_ADDR", "0.0.0.0:"+port)
	if err := healthcheck(); err != nil {
		t.Fatalf("healthy server reported unhealthy: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := healthcheck(); err == nil {
		t.Fatal("503 reported healthy")
	}
	t.Setenv("LISTEN_ADDR", "127.0.0.1:1")
	if err := healthcheck(); err == nil {
		t.Fatal("unreachable server reported healthy")
	}
	t.Setenv("LISTEN_ADDR", "bogus")
	if err := healthcheck(); err == nil {
		t.Fatal("bad address accepted")
	}
}
