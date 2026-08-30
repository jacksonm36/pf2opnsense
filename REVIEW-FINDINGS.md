# Full-project review: bugs, issues, and config errors

Review of the pfSense → OPNsense 26.7 converter (`pf2opn`), covering mapper, validator, XML codec, CLI, and HTTP server. Findings were confirmed against the live code and, where noted, by running the converter on the sample configs.

This document is the written record of the review. The same batch of changes that added this file also fixes the confirmed items below.

## Critical (broken or unsafe config)

### 1. IPsec is always written as enabled

`mapIPsec` hardcoded `OPNsense/IPsec/general/enabled = 1` and never read pfSense’s `<ipsec><enable>` presence flag. Sample configs with IPsec off (`pfsense-3.xml`, `complex-pfsense.xml`) would start dialing tunnels on first boot after restore.

**Fix:** write `enabled` from `FlagSet(src["enable"])`. Tunnels are still mapped so they appear in the UI, but the service stays off until the operator turns it on.

### 2. AEAD (GCM/CCM) ESP proposals are invalid

`p2Proposals` / `oneProposal` always appended an integrity algorithm (`aes256gcm-sha256-modp2048`). strongSwan rejects AEAD proposals that also carry a hash, so the child SA never comes up. `encTokens` also dropped the GCM ICV length (`keylen` 64/96/128), so `aes256gcm8` / `gcm12` silently became ICV-16 and would not match the peer.

**Fix:** do not attach a hash to GCM/CCM tokens; map ICV length to the `gcm8` / `gcm12` / `gcm16` suffix.

### 3. Disabled pfSense DHCP scopes become live DHCP servers

`collectDhcpd` skipped only `enable == "0"`. pfSense never writes that value: an enabled scope is an empty `<enable/>` tag, and a disabled scope omits the tag. Confirmed on `complex-pfsense.xml` (`dhcpd/lan` has a range and no `<enable>`): the output previously emitted an active `dhcp_ranges`.

**Fix:** skip unless `FlagSet(enable)`. `sourceHasDHCP` uses the same rule so the validator does not fail a correctly empty mapping.

### 4. Revision timestamp is scientific notation

`fmt.Sprintf("%v", float64(unixMilli)/1000)` yields values like `1.788065925103e+09`. OPNsense stores plain decimal seconds and its config-history UI reads this field.

**Fix:** `strconv.FormatFloat(..., 'f', 4, 64)` via `revisionUnixTime()`.

### 5. Deeply nested XML can kill the HTTP server

`xmlutil.Parse` recurses once per nesting level. A hostile `<a><a><a>…` body under the 32 MiB upload cap overflows the goroutine stack (`fatal error`, not a panic), so `net/http` recover cannot catch it.

**Fix:** `maxDepth = 256` in the parser (already present; covered by a test).

### 6. Converted `config.xml` is world-readable

`os.Create` uses 0666 & umask (typically 0664). The file contains CA/cert private keys, IPsec PSKs, WireGuard keys, and password hashes.

**Fix:** `os.OpenFile(..., 0o600)` and surface write/close errors instead of exiting 0 on a truncated file.

## High (silently wrong output)

| Area | Issue | Fix |
| --- | --- | --- |
| Swanctl lift | Section-level “real mount wins” could keep `children`/`locals`/`remotes` while dropping the nested `Connections` they reference | Item-level merge, dedup on `@_uuid` |
| Mobile IPsec | Phase 1s without `remote-gateway` (road warrior) dropped; note only fired when *no* site-to-site tunnel existed | Always note dropped mobile phase 1s |
| IPv6 IPsec | `interfaceBindAddr` and interface traffic selectors read IPv4 only | Fall back to `ipaddrv6` / `subnetv6` (tunnel6 uses v6) |
| VTI children | `mode=vti` became `tunnel` with `policies=1`, installing kernel policies on a route-based tunnel | `policies=0` for VTI |
| Extra DHCP pools | Only the primary `<range>` was read; extra `<pool>` blocks discarded | Collect every pool range |
| Kea `domainsearchlist` | Semicolon-separated pfSense list passed through | Split on `;`, `,`, and whitespace |
| Kea skip | Skipping a subnet with no CIDR also dropped its reservations with no count | Note how many reservations were skipped |
| Kea autocollect | `option_data_autocollect=1` alongside explicit options | Set autocollect to `0` when options are present |
| Kea merge panic | Empty CIDR keyed `cidrToIdx[""]`; nil subnet map assignment | Require a real CIDR and nil-check the subnet |
| Disabled Kea | `collectKeaScopes` returned nil when `enabled=0`, then `writeOpnKea(nil)` deleted subnets | Collect scopes even when the server is disabled |
| dnsmasq strip | Removing DHCP hosts also cleared `enable`, turning off DNS | Keep `enable` when it was set |
| dnsmasq bind | Invalid interface list deleted `interface`, so dnsmasq listened on every NIC | Leave the original list when nothing validates |
| ikeid fallback | Synthetic `len(connections)+1` could collide with a later real `ikeid` | Reserve existing ikeids before allocating |
| Reqid drop | Out-of-range reqid became `""` with no note | Note the drop |
| Cron | `configctl interface reload wan` was stored as the whole `command` | Split action vs `parameters`; strip redirects |
| Cron schedule | Empty `minute`/`hour` defaulted to `0`, not `*` | Default all five fields to `*` when empty |
| CLI | `pf2opn convert in.xml -json` created a file named `-json` | Reject leftover flag-like args |
| Server | Case-sensitive `multipart/` match; form-urlencoded body treated as XML; oversize → 400; `unix:` unlink of any path | `mime.ParseMediaType`; reject unexpected types; 413; only replace an existing socket |
| `local_addrs` / selectors | `networkCIDR` parse failure returned `addr/255.255.255.0` | Return empty on parse failure |
| Responder-only | `responderonly` ignored; children always `start_action=start` | `start_action=none` when the phase 1 is responder-only |

## Validator

- **Interface names** were joined in map-iteration order (non-deterministic report text). Now sorted.
- **Alias “glued IP” regex** matched ordinary `192.168.1.10 10.0.0.20` pairs. Now requires two IPv4 addresses with no separator.
- **OpenVPN `remote`** used `AsString` on a forced array, so two `<remote>` children skipped validation. Each value is checked.
- **WireGuard names** shared one uniqueness map across instances and peers (separate OPNsense models). Two maps now.
- **Proposal tokens** rejected valid strongSwan aliases (`sha2_256`, `modpnone`, `prfsha256`, PQ `ke1_*`). Those are accepted; unknown tokens warn; tokens containing `auto` still fail.
- **IPsec model errors** were not deduped; dangling children were ignored when no Connection had a UUID.
- **WireGuard** failed when tunnels mapped to zero servers, but not when peers mapped to zero clients.
- **`vpnid`** is trimmed and normalized (`01` and `1` collide) before the uniqueness check.
- **DynDNS / nested Swanctl presence** now uses `IsEmptySection` where a bare `!= nil` missed empty tags.

## Lower (accepted or partial)

- **Double entity decode** (`html.UnescapeString` after `dec.Entity = xml.HTMLEntity`): needed for `Jos&amp;eacute;` in real pfSense backups. Ordinary `&amp;` in URLs still round-trips. Left as-is; documented here.
- **Empty `ArrayTags` elements** (`<cert></cert>`) still disappear on write. Harmless for these schemas.
- **`FlagSet("no")`** already treated as false in this tree.
- **Parse depth** already capped at 256; test added.
- **WINS / IPv6 DHCP / `filename32`**: still unmapped; conversion notes mention dropped DHCP options (gateway, DNS, TFTP) on the dnsmasq path.
- **No graceful HTTP shutdown** and no in-flight request limiter: not changed.

## How to verify

```bash
go test ./...
go run ./cmd/pf2opn convert sample-files/complex-pfsense.xml -json | head
```

Expect: no `dhcp_ranges` from a disabled `dhcpd/lan`; IPsec `general/enabled` is `0` when pfSense had no `<ipsec><enable/>`; revision `<time>` is a plain decimal.
