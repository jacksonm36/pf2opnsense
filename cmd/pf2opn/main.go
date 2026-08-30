package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/convert"
	"github.com/jacksonm36/pf2opnsense/internal/mapper"
	"github.com/jacksonm36/pf2opnsense/internal/server"
	"github.com/jacksonm36/pf2opnsense/web"
)

const version = "0.4.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		listen := fs.String("listen", server.DefaultListen, "listen address (default 127.0.0.1:8080). Docker/OPNsense WAN-facing binds should stay loopback; use :8080 only inside a container.")
		_ = fs.Parse(os.Args[2:])
		if err := server.ListenAndServe(*listen, web.Static); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "convert":
		fs := flag.NewFlagSet("convert", flag.ExitOnError)
		pretty := fs.Bool("pretty", true, "pretty-print XML")
		jsonOut := fs.Bool("json", false, "print validation JSON instead of XML")
		dhcp := fs.String("dhcp", mapper.DhcpDnsmasq, "DHCP backend: dnsmasq (default) or kea")
		_ = fs.Parse(os.Args[2:])
		args := fs.Args()
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				fmt.Fprintln(os.Stderr, "flags must come before the input filename, e.g. pf2opn convert -json in.xml")
				os.Exit(2)
			}
		}
		inName, raw := readInput(args)
		result := convert.Run(inName, raw, &mapper.Options{DhcpBackend: mapper.ParseDhcpBackend(*dhcp)})
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(result)
			if !result.Validation.CanDownload {
				os.Exit(2)
			}
			return
		}
		xml := result.XML
		if !*pretty {
			xml = result.CompactXML
		}
		if xml == "" {
			fmt.Fprintln(os.Stderr, "conversion blocked by validators")
			enc := json.NewEncoder(os.Stderr)
			enc.SetIndent("", "  ")
			_ = enc.Encode(result.Validation)
			os.Exit(2)
		}
		if len(args) >= 2 {
			f, err := os.OpenFile(args[1], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if _, err := io.WriteString(f, xml); err != nil {
				_ = f.Close()
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !strings.HasSuffix(xml, "\n") {
				if _, err := io.WriteString(f, "\n"); err != nil {
					_ = f.Close()
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
			}
			if err := f.Close(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
		if _, err := io.WriteString(os.Stdout, xml); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !strings.HasSuffix(xml, "\n") {
			_, _ = io.WriteString(os.Stdout, "\n")
		}
	case "version", "-v", "--version":
		fmt.Println("pf2opn", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func readInput(args []string) (string, string) {
	if len(args) == 0 || args[0] == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return "stdin.xml", string(data)
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return filepath.Base(args[0]), string(data)
}

func usage() {
	fmt.Fprintf(os.Stderr, `pf2opn %s — pfSense 2.7.0 or OPNsense → OPNsense 26.7 series converter

Usage:
  pf2opn serve [-listen 127.0.0.1:8080]
  pf2opn convert [-pretty=true] [-json] [-dhcp=dnsmasq|kea] [in.xml [out.xml]]
  pf2opn version

The mapped config.xml is for OPNsense 26.7.3 and the rest of the 26.7 series.
ISC dhcpd (pfSense) and dnsmasq/Kea (OPNsense) map to -dhcp=dnsmasq (default) or -dhcp=kea.

serve starts a native HTTP server (static UI + POST /api/convert) on loopback.
On OPNsense, keep the default and let lighttpd/nginx proxy to 127.0.0.1:8080
(see deploy/lighttpd.conf). The converted XML is unchanged.

  pf2opn serve
  pf2opn serve -listen 127.0.0.1:8080
  pf2opn serve -listen unix:/run/pf2opn.sock

convert reads XML from a file or stdin and writes OPNsense XML.
`, version)
}
