package server

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListenUnixMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pf2opn.sock")
	ln, err := listenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if mode&0o007 != 0 {
		t.Fatalf("socket is world-accessible: %o", mode)
	}
	if mode&0o660 != 0o660 && mode&0o600 != 0o600 {
		t.Fatalf("socket should be owner/group read-write, got %o", mode)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestListenUnixRefusesRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(path); err == nil {
		t.Fatal("expected refusal to replace a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatalf("regular file was modified: %v %q", err, data)
	}
}
