package mapper

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

// OPNsense model versions for //OPNsense/wireguard/{general,client,server}.
const (
	wgGeneralVersion = "0.0.1"
	wgClientVersion  = "1.0.0"
	wgServerVersion  = "1.0.1"
)

var (
	wgNameAllowed  = regexp.MustCompile(`[^0-9a-zA-Z._\-]+`)
	wgTrailingNumR = regexp.MustCompile(`(\d+)$`)
)

// mapWireGuard converts the pfSense WireGuard package
// (installedpackages/wireguard) into OPNsense's core WireGuard model. It
// returns the OPNsense/wireguard block and the tun_wgN -> wgN device renames
// that interface assignments and firewall rules need.
func mapWireGuard(pfsense map[string]any, opt *Options, report *Notes) (map[string]any, map[string]string) {
	src := xmlutil.Map(xmlutil.Get(pfsense, "installedpackages", "wireguard"))
	if src == nil {
		src = xmlutil.Map(pfsense["wireguard"])
	}
	if src == nil {
		return nil, nil
	}
	tunnels := xmlutil.AsArray(xmlutil.Get(src, "tunnels", "item"))
	peers := xmlutil.AsArray(xmlutil.Get(src, "peers", "item"))
	if len(tunnels)+len(peers) == 0 {
		return nil, nil
	}

	// Peers carry the tunnel they belong to by pfSense device name.
	peersByTunnel := map[string][]any{}
	unassigned := 0
	for _, raw := range peers {
		tun := xmlutil.LowerIdent(xmlutil.Map(raw)["tun"])
		if tun == "" || tun == "unassigned" {
			unassigned++
			tun = ""
		}
		peersByTunnel[tun] = append(peersByTunnel[tun], raw)
	}

	names := newNameSet()
	instances := map[int]struct{}{}
	clients, servers := []any{}, []any{}
	renames := map[string]string{}
	skipped := 0

	for _, raw := range tunnels {
		tun := xmlutil.Map(raw)
		device := xmlutil.LowerIdent(tun["name"])
		label := orDefault(xmlutil.AsString(tun["descr"]), device)

		// privkey is Required; without it OPNsense cannot bring the interface up.
		privkey := strings.TrimSpace(xmlutil.AsString(tun["privatekey"]))
		if privkey == "" {
			skipped++
			report.Skipped = append(report.Skipped, fmt.Sprintf(
				`Skipped WireGuard tunnel "%s": pfSense stored no private key, which OPNsense requires.`, label))
			continue
		}

		instance := wgInstance(device, instances)
		instances[instance] = struct{}{}
		if device != "" {
			renames[device] = fmt.Sprintf("wg%d", instance)
		}

		peerUUIDs := []string{}
		for _, praw := range peersByTunnel[device] {
			client, uuid := mapWireGuardPeer(praw, names, opt, report)
			clients = append(clients, client)
			peerUUIDs = append(peerUUIDs, uuid)
		}
		delete(peersByTunnel, device)

		server := map[string]any{
			"@_uuid":        nextUUID(opt),
			"enabled":       xmlutil.Present01(xmlutil.YesFlag(tun["enabled"])),
			"name":          names.take(xmlutil.AsString(tun["descr"]), device, fmt.Sprintf("wg%d", instance)),
			"instance":      strconv.Itoa(instance),
			"privkey":       privkey,
			"pubkey":        strings.TrimSpace(xmlutil.AsString(tun["publickey"])),
			"port":          strings.TrimSpace(xmlutil.AsString(tun["listenport"])),
			"mtu":           wgMTU(tun["mtu"]),
			"tunneladdress": wgAddressList(tun["addresses"]),
			"disableroutes": "0",
			"debug":         "0",
		}
		if len(peerUUIDs) > 0 {
			server["peers"] = strings.Join(peerUUIDs, ",")
		}
		servers = append(servers, server)
	}

	// Peers pfSense left unassigned, plus any left behind by a skipped or
	// missing tunnel, still belong in the peer list so the user can attach
	// them. No instance references them.
	orphans := 0
	for _, tun := range sortedPeerKeys(peersByTunnel) {
		for _, praw := range peersByTunnel[tun] {
			client, _ := mapWireGuardPeer(praw, names, opt, report)
			clients = append(clients, client)
			if tun != "" {
				orphans++
			}
		}
	}
	unassigned += orphans

	if len(servers)+len(clients) == 0 {
		return nil, nil
	}

	enabled := xmlutil.Present01(xmlutil.YesFlag(xmlutil.Get(firstItem(src["config"]), "enable")))
	block := map[string]any{
		"general": map[string]any{"@_version": wgGeneralVersion, "enabled": enabled},
	}
	if len(clients) > 0 {
		block["client"] = map[string]any{
			"@_version": wgClientVersion,
			"clients":   map[string]any{"client": clients},
		}
	}
	if len(servers) > 0 {
		block["server"] = map[string]any{
			"@_version": wgServerVersion,
			"servers":   map[string]any{"server": servers},
		}
	}

	report.Stats.WireguardTunnels = len(servers)
	report.Stats.WireguardPeers = len(clients)
	report.Notes = append(report.Notes, fmt.Sprintf(
		"Mapped the pfSense WireGuard package to OPNsense's built-in WireGuard: %d instance(s), %d peer(s) under VPN → WireGuard. WireGuard is part of OPNsense %s, so no plugin is needed.",
		len(servers), len(clients), OpnTarget()))
	if len(renames) > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"Renamed WireGuard devices to OPNsense names (%s) in interface assignments and firewall rules.",
			strings.Join(renamePairs(renames), ", ")))
	}
	if unassigned > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"%d WireGuard peer(s) were unassigned in pfSense. They were imported but no instance lists them; attach them under VPN → WireGuard → Instances.",
			unassigned))
	}
	if skipped > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"%d WireGuard tunnel(s) had no private key and were skipped. pfSense hides keys when 'Hide Secrets' is on — export the config again with secrets visible.",
			skipped))
	}
	return block, renames
}

func mapWireGuardPeer(raw any, names *nameSet, opt *Options, report *Notes) (map[string]any, string) {
	peer := xmlutil.Map(raw)
	uuid := nextUUID(opt)
	name := names.take(xmlutil.AsString(peer["descr"]), "", "peer")
	client := map[string]any{
		"@_uuid":        uuid,
		"enabled":       xmlutil.Present01(xmlutil.YesFlag(peer["enabled"])),
		"name":          name,
		"pubkey":        strings.TrimSpace(xmlutil.AsString(peer["publickey"])),
		"psk":           strings.TrimSpace(xmlutil.AsString(peer["presharedkey"])),
		"tunneladdress": wgAddressList(peer["allowedips"]),
	}
	if endpoint := strings.TrimSpace(xmlutil.AsString(peer["endpoint"])); endpoint != "" {
		client["serveraddress"] = endpoint
		if port := strings.TrimSpace(xmlutil.AsString(peer["port"])); port != "" {
			client["serverport"] = port
		}
	}
	if ka := wgKeepalive(peer["persistentkeepalive"]); ka != "" {
		client["keepalive"] = ka
	}
	if xmlutil.AsString(client["pubkey"]) == "" {
		report.Notes = append(report.Notes, fmt.Sprintf(
			`WireGuard peer "%s" has no public key; OPNsense requires one. Add it under VPN → WireGuard → Peers.`, name))
	}
	if xmlutil.AsString(client["tunneladdress"]) == "" {
		report.Notes = append(report.Notes, fmt.Sprintf(
			`WireGuard peer "%s" has no allowed IPs; OPNsense requires at least one. Add it under VPN → WireGuard → Peers.`, name))
	}
	return client, uuid
}

// wgAddressList turns pfSense's <addresses><row><address>/<mask> rows into the
// comma separated CIDR list OPNsense stores. Both tunneladdress fields have
// NetMaskRequired set, so a bare address gets a host mask.
func wgAddressList(node any) string {
	out := []string{}
	for _, raw := range xmlutil.AsArray(xmlutil.Get(node, "row")) {
		row := xmlutil.Map(raw)
		addr := strings.TrimSpace(xmlutil.AsString(row["address"]))
		if addr == "" {
			continue
		}
		if strings.Contains(addr, "/") {
			out = append(out, addr)
			continue
		}
		mask := strings.TrimSpace(xmlutil.AsString(row["mask"]))
		if mask == "" {
			mask = ifThen(strings.Contains(addr, ":"), "128", "32")
		}
		out = append(out, addr+"/"+mask)
	}
	return strings.Join(uniqueNonEmpty(out), ",")
}

// wgInstance keeps the number pfSense used in tun_wgN so the OPNsense device
// name (wgN) lines up with the old one wherever possible.
func wgInstance(device string, used map[int]struct{}) int {
	if m := wgTrailingNumR.FindStringSubmatch(device); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n >= 0 {
			if _, taken := used[n]; !taken {
				return n
			}
		}
	}
	for n := 0; ; n++ {
		if _, taken := used[n]; !taken {
			return n
		}
	}
}

func wgMTU(value any) string {
	n, err := strconv.Atoi(strings.TrimSpace(xmlutil.AsString(value)))
	if err != nil || n < 1 || n > 9300 {
		return "1420"
	}
	return strconv.Itoa(n)
}

func wgKeepalive(value any) string {
	n, err := strconv.Atoi(strings.TrimSpace(xmlutil.AsString(value)))
	if err != nil || n < 1 || n > 65535 {
		return ""
	}
	return strconv.Itoa(n)
}

// nameSet hands out names that satisfy the WireGuard model's
// /^([0-9a-zA-Z._\-]){1,64}$/ mask and stay unique within the config.
type nameSet struct {
	seen map[string]struct{}
}

func newNameSet() *nameSet {
	return &nameSet{seen: map[string]struct{}{}}
}

func (n *nameSet) take(candidates ...string) string {
	base := ""
	for _, candidate := range candidates {
		if base = sanitizeWgName(candidate); base != "" {
			break
		}
	}
	if base == "" {
		base = "wg"
	}
	name := base
	for i := 2; ; i++ {
		if _, taken := n.seen[strings.ToLower(name)]; !taken {
			n.seen[strings.ToLower(name)] = struct{}{}
			return name
		}
		name = fmt.Sprintf("%s_%d", base, i)
	}
}

func sanitizeWgName(raw string) string {
	clean := wgNameAllowed.ReplaceAllString(strings.TrimSpace(raw), "_")
	clean = strings.Trim(clean, "_")
	if len(clean) > 64 {
		clean = strings.Trim(clean[:64], "_")
	}
	return clean
}

func sortedPeerKeys(m map[string][]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstItem(value any) any {
	if arr := xmlutil.AsArray(value); len(arr) > 0 {
		return arr[0]
	}
	return value
}

func renamePairs(renames map[string]string) []string {
	from := make([]string, 0, len(renames))
	for k := range renames {
		from = append(from, k)
	}
	sort.Strings(from)
	out := make([]string, 0, len(from))
	for _, k := range from {
		out = append(out, k+" → "+renames[k])
	}
	return out
}
