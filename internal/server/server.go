package server

import (
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/jacksonm36/pf2opnsense/internal/convert"
	"github.com/jacksonm36/pf2opnsense/internal/mapper"
)

const DefaultListen = "127.0.0.1:8080"

func ListenAndServe(addr string, web fs.FS) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/convert", handleConvert)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	sub, err := fs.Sub(web, "static")
	if err != nil {
		return err
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("/", fileServer)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	if strings.HasPrefix(addr, "unix:") {
		path := strings.TrimPrefix(addr, "unix:")
		ln, err := listenUnix(path)
		if err != nil {
			return err
		}
		log.Printf("pf2opn listening on unix:%s (mode 0660)", path)
		return srv.Serve(ln)
	}
	if host, _, err := net.SplitHostPort(addr); err == nil && (host == "" || host == "0.0.0.0" || host == "::") {
		log.Printf("warning: listening on all interfaces (%s); prefer 127.0.0.1:8080 behind OPNsense lighttpd/nginx", addr)
	}
	log.Printf("pf2opn listening on %s", addr)
	srv.Addr = addr
	return srv.ListenAndServe()
}

// listenUnix binds a socket that the same user (and, on OPNsense, group www) can use.
// Mode 0660 so a local reverse proxy can connect without making the socket world-writable.
func listenUnix(path string) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return nil, err
	}
	grantProxyGroup(path)
	return ln, nil
}

func grantProxyGroup(path string) {
	for _, name := range []string{"www", "www-data"} {
		g, err := user.LookupGroup(name)
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			continue
		}
		if err := os.Chown(path, -1, gid); err != nil {
			continue
		}
		log.Printf("unix socket group set to %s for the local reverse proxy", name)
		return
	}
}

func handleConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST a pfSense config.xml", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	name, raw, err := readUpload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	backend := r.FormValue("dhcp")
	if backend == "" {
		backend = r.URL.Query().Get("dhcp")
	}
	result := convert.Run(name, raw, &mapper.Options{DhcpBackend: mapper.ParseDhcpBackend(backend)})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func readUpload(r *http.Request) (string, string, error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return "", "", err
		}
		file, hdr, err := r.FormFile("file")
		if err != nil {
			file, hdr, err = r.FormFile("config")
		}
		if err != nil {
			return "", "", err
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			return "", "", err
		}
		return hdr.Filename, string(data), nil
	}
	data, err := io.ReadAll(r.Body)
	return "config.xml", string(data), err
}
