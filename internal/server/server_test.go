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
