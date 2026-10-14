package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRelayStartupFailureRemovesBoundControlSocket(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	c := testConfig(t, server.URL)
	occupied, err := net.Listen("tcp", c.ListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if r, err := newRelay(c); err == nil {
		r.Close()
		t.Fatal("relay started on an occupied listen address")
	}
	if _, err := os.Lstat(c.ControlSocket); !os.IsNotExist(err) {
		t.Fatalf("failed startup left the control socket behind: %v", err)
	}
}
