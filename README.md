# pf2opnsense

pfSense 2.7.0 (config revision 22.9) or OPNsense → OPNsense **26.7 series** converter (including **26.7.3**). pfSense backups are mapped into the 26.7 MVC layout. OPNsense backups are preserved, with DHCP remapped between **dnsmasq** and **Kea**.

The converter is a **native Go binary**. It maps the backup on the machine that runs it, then either writes XML to stdout or serves a small web UI.

Derived from the [pf2opn](https://github.com/mwood77/pf2opn) project (CC BY-NC 4.0).

What is mapped into the current OPNsense 26.7 layout:

- Filter rules → `OPNsense/Firewall/Filter` (MVC). Legacy `<filter>` is left empty so you do not have to migrate old rules by hand.
- Aliases → `OPNsense/Firewall/Alias` with newline-separated content.
- Gateways → `OPNsense/Gateways` (weight clamped to 1–10).
- Interface assignments, VLANs, NAT port forwards.
- ISC dhcpd (pfSense) or dnsmasq/Kea (OPNsense) → **dnsmasq** (default) or **Kea** DHCPv4. Choose in the UI or pass `-dhcp=kea`. Do not enable both DHCP servers on the same LAN.
- OpenVPN **Instances**: servers and clients become `OPNsense/OpenVPN/Instances`, TLS keys become `StaticKeys`, and per-user CSC entries become `Overwrites`. Legacy `openvpn-server` / `openvpn-csc` XML is not written.
- DynDNS → `OPNsense/DynDNS` (os-ddclient). Legacy `<dyndnses>` is not written.
- IPsec → `OPNsense/Swanctl` connections and `OPNsense/IPsec` pre-shared keys.
- pfSense `installedpackages` records (for reference; install matching OPNsense plugins separately).

Not mapped: pfSense packages (pfBlockerNG, etc.), traffic shaper, captive portal, WireGuard package config, `match` filter actions.

## Native binary

The web UI is Svelte (Vite). It compiles to static files that are embedded in the binary.

```
cd web/ui && npm ci && npm run build && cd ../..
go build -o pf2opn ./cmd/pf2opn
```

UI live reload (proxies `/api` to the binary on `:8080`):

```
./pf2opn serve -listen :8080
cd web/ui && npm run dev
```

Then open `http://127.0.0.1:5173`.

CLI conversion (validators must pass or the process exits 2 and prints no XML):

```
./pf2opn convert config.xml opnsense.xml
./pf2opn convert -dhcp=kea config.xml opnsense.xml
./pf2opn convert -json config.xml
cat config.xml | ./pf2opn convert -pretty=false > opnsense.xml
```

HTTP server (UI + `POST /api/convert`):

```
./pf2opn serve
./pf2opn serve -listen :8080
./pf2opn serve -listen 127.0.0.1:8080
./pf2opn serve -listen unix:/run/pf2opn.sock
```

Then open `http://127.0.0.1:8080`. Conversion runs **in the binary**, not in the browser.

### nginx

```
./pf2opn serve -listen 127.0.0.1:8080
```

Use `deploy/nginx.conf` (`proxy_pass http://127.0.0.1:8080` and `client_max_body_size 32m`). For a unix socket:

```
./pf2opn serve -listen unix:/run/pf2opn.sock
```

```
proxy_pass http://unix:/run/pf2opn.sock:;
```

### lighttpd

Same idea with `deploy/lighttpd.conf` (`mod_proxy` to `127.0.0.1:8080`, or `host` set to `/run/pf2opn.sock`).

## Docker

```
docker compose up --build
```

Navigate to [`localhost:4200`](http://localhost:4200). The image is the Go binary listening on 8080 (host port 4200).

```
docker build -t pf2opn .
docker run --name pf2opn -p 4200:8080 -d pf2opn
```

## Tests

```
go test ./...
```

The TypeScript mapper under `src/` is a leftover reference. Production conversion is the Go binary; the production UI is Svelte under `web/ui`.
