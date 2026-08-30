package server

import (
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/convert"
	"github.com/jacksonm36/pf2opnsense/internal/mapper"
)

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

	if strings.HasPrefix(addr, "unix:") {
		path := strings.TrimPrefix(addr, "unix:")
		_ = os.Remove(path)
		ln, err := net.Listen("unix", path)
		if err != nil {
			return err
		}
		_ = os.Chmod(path, 0o666)
		log.Printf("pf2opn listening on unix:%s", path)
		return http.Serve(ln, mux)
	}
	log.Printf("pf2opn listening on %s", addr)
	return http.ListenAndServe(addr, mux)
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
