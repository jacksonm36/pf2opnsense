# pf2opnsense

pfSense 2.7.0 (config revision 22.9) or OPNsense → OPNsense **26.7 series** converter (including **26.7.3**). pfSense backups are mapped into the 26.7 MVC layout. OPNsense backups are preserved, with DHCP remapped between **dnsmasq** and **Kea**.

The converter is a **native Go binary**. It maps the backup on the machine that runs it, then either writes XML to stdout or serves a small web UI.

Original author: [mwood77](https://github.com/mwood77). This repository is derived from [pf2opn](https://github.com/mwood77/pf2opn) (CC BY-NC 4.0).

What is mapped into the current OPNsense 26.7 layout:

- Filter rules → `OPNsense/Firewall/Filter` (MVC). Legacy `<filter>` is left empty so you do not have to migrate old rules by hand.
- Aliases → `OPNsense/Firewall/Alias` with newline-separated content.
- Gateways → `OPNsense/Gateways` (weight clamped to 1–10).
- Interface assignments, VLANs, NAT port forwards.
- ISC dhcpd (pfSense) or dnsmasq/Kea (OPNsense) → **dnsmasq** (default) or **Kea** DHCPv4. Choose in the UI or pass `-dhcp=kea`. Do not enable both DHCP servers on the same LAN.
- OpenVPN **Instances**: servers and clients become `OPNsense/OpenVPN/Instances`, TLS keys become `StaticKeys`, and per-user CSC entries become `Overwrites`. Legacy `openvpn-server` / `openvpn-csc` XML is not written. pfSense numbers servers and clients separately, so colliding `vpnid` values are renumbered into the single OPNsense Instances list — OPNsense derives `dev-node /dev/tun<vpnid>` from it, and a duplicate makes the second daemon die with `Device busy`. Keepalive defaults to pfSense's `10 60` so OpenVPN still does dead-peer detection.
- WireGuard → `OPNsense/wireguard` (built into OPNsense 26.7, no plugin needed). pfSense tunnels become instances, peers become peers, and `tun_wgN` devices are renamed to `wgN` in interface assignments and firewall rules.
- DynDNS → `OPNsense/DynDNS` (os-ddclient). Legacy `<dyndnses>` is not written.
- IPsec → `OPNsense/Swanctl` connections and `OPNsense/IPsec` pre-shared keys.
- pfSense `installedpackages` records (for reference; install matching OPNsense plugins separately).

Not mapped: pfSense packages (pfBlockerNG, etc.), traffic shaper, captive portal, `match` filter actions.

## Native binary

The web UI is Svelte (Vite). It compiles to static files that are embedded in the binary.

```
cd web/ui && npm ci && npm run build && cd ../..
go build -o pf2opn ./cmd/pf2opn
```

UI live reload (proxies `/api` to the binary on loopback `:8080`):

```
./pf2opn serve
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

HTTP server (UI + `POST /api/convert`). Default listen is **127.0.0.1:8080** so the API is not on LAN/WAN. On OPNsense, leave that default and proxy with `deploy/lighttpd.conf` or `deploy/nginx.conf`. Mapped `config.xml` content is unchanged.

```
./pf2opn serve
./pf2opn serve -listen 127.0.0.1:8080
./pf2opn serve -listen unix:/run/pf2opn.sock
```

Then open `http://127.0.0.1:8080`. Conversion runs **in the binary**, not in the browser. Unix sockets are mode `0660` (group `www` on OPNsense) so lighttpd can connect without a world-writable socket.

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

Navigate to [`http://127.0.0.1:4200`](http://127.0.0.1:4200). Add a second host-IP mapping in `docker-compose.yml` if you need LAN access (do not publish `0.0.0.0`). The image listens on 8080 inside the container.

```
docker build -t pf2opn .
docker run --name pf2opn -p 127.0.0.1:4200:8080 -d pf2opn
```

## Tests

```
go test ./...
```

The TypeScript mapper under `src/` is leftover reference and is not built. Do not `npm install` at the repo root. Production conversion is the Go binary; the production UI is Svelte under `web/ui`.
