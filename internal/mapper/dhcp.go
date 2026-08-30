package mapper

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

func mapDHCP(pfsense map[string]any, opt *Options, report *Notes) (dnsmasq, kea map[string]any) {
	if dhcpBackend(opt) == DhcpKea {
		return mapDhcpToKea(pfsense, opt, report)
	}
	return mapDhcpToDnsmasq(pfsense, opt, report), nil
}

func mapDhcpToDnsmasq(pfsense map[string]any, opt *Options, report *Notes) map[string]any {
	return dnsmasqFromScopes(pfsense, collectDhcpd(pfsense), opt, report)
}

func dnsmasqFromScopes(pfsense map[string]any, scopes []dhcpScope, opt *Options, report *Notes) map[string]any {
	existing := xmlutil.Map(pfsense["dnsmasq"])
	if existing == nil {
		existing = map[string]any{}
	}
	ranges := []any{}
	hosts := []any{}
	ifaces := []string{}
	for _, scope := range scopes {
		ifaces = append(ifaces, scope.iface)
		for _, rng := range scope.ranges {
			ranges = append(ranges, map[string]any{
				"@_uuid":     nextUUID(opt),
				"interface":  scope.iface,
				"start_addr": rng.from,
				"end_addr":   rng.to,
			})
		}
		for _, m := range scope.static {
			ip, mac := xmlutil.AsString(m["ipaddr"]), xmlutil.AsString(m["mac"])
			if ip == "" && mac == "" {
				continue
			}
			hosts = append(hosts, map[string]any{
				"@_uuid": nextUUID(opt),
				"host":   xmlutil.AsString(m["hostname"]),
				"ip":     ip,
				"hwaddr": mac,
				"descr":  xmlutil.AsString(m["descr"]),
			})
		}
	}
	for _, host := range xmlutil.AsArray(existing["hosts"]) {
		h := xmlutil.Map(host)
		item := map[string]any{
			"host": xmlutil.AsString(h["host"]), "domain": xmlutil.AsString(h["domain"]),
			"ip": xmlutil.AsString(h["ip"]), "descr": xmlutil.AsString(h["descr"]),
		}
		if uuid := xmlutil.AsString(h["@_uuid"]); uuid != "" {
			item["@_uuid"] = uuid
		} else {
			item["@_uuid"] = nextUUID(opt)
		}
		hosts = append(hosts, item)
	}
	if len(ranges) == 0 && len(hosts) == 0 && !xmlutil.FlagSet(existing["enable"]) {
		return nil
	}
	report.Stats.DhcpRanges = len(ranges)
	report.Stats.DhcpHosts = len(hosts)
	if len(ranges) > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"Mapped DHCP pools to dnsmasq DHCP (%s default for small/medium networks).", OpnSeries))
	}
	mapped := map[string]any{
		"enable":    "1",
		"port":      orDefault(xmlutil.AsString(existing["port"]), "53053"),
		"interface": strings.Join(validDhcpIfaces(pfsense, ifaces), ","),
		"dhcp":      map[string]any{"enable_ra": "1"},
	}
	if mapped["interface"] == "" {
		mapped["interface"] = strings.Join(validDhcpIfaces(pfsense, splitCSV(xmlutil.AsString(existing["interface"]))), ",")
	}
	if len(ranges) > 0 {
		mapped["dhcp_ranges"] = ranges
	}
	if len(hosts) > 0 {
		mapped["hosts"] = hosts
	}
	return mapped
}

func mapDhcpToKea(pfsense map[string]any, opt *Options, report *Notes) (dnsmasq, kea map[string]any) {
	return keaFromScopes(pfsense, collectDhcpd(pfsense), opt, report)
}

func keaFromScopes(pfsense map[string]any, scopes []dhcpScope, opt *Options, report *Notes) (dnsmasq, kea map[string]any) {
	subnets := []any{}
	reservations := []any{}
	ifaces := []string{}
	inPool := 0
	for _, scope := range scopes {
		cidr := interfaceCIDR(pfsense, scope.iface)
		if cidr == "" {
			report.Notes = append(report.Notes, fmt.Sprintf(
				"Skipped Kea subnet for %s: the interface has no static IPv4 prefix to derive a CIDR from.", scope.iface))
			continue
		}
		ifaces = append(ifaces, scope.iface)
		subnetUUID := nextUUID(opt)
		pools := joinKeaPools(scope.ranges)
		subnet := map[string]any{
			"@_uuid":                  subnetUUID,
			"subnet":                  cidr,
			"description":             orDefault(interfaceDescr(pfsense, scope.iface), strings.ToUpper(scope.iface)),
			"option_data_autocollect": "1",
			"pools":                   pools,
		}
		if next := xmlutil.AsString(scope.cfg["nextserver"]); next != "" {
			subnet["next_server"] = next
		}
		if optData := keaOptionData(pfsense, scope.cfg); len(optData) > 0 {
			subnet["option_data"] = optData
		}
		subnets = append(subnets, subnet)
		for _, m := range scope.static {
			ip := xmlutil.AsString(m["ipaddr"])
			mac := normalizeMAC(xmlutil.AsString(m["mac"]))
			cid := strings.TrimSpace(xmlutil.AsString(m["cid"]))
			if ip == "" && mac == "" && cid == "" {
				continue
			}
			if mac == "" && cid == "" {
				report.Notes = append(report.Notes, fmt.Sprintf(
					"Skipped Kea reservation %s on %s: Kea needs a MAC or client-id.", ip, scope.iface))
				continue
			}
			item := map[string]any{
				"@_uuid":      nextUUID(opt),
				"subnet":      subnetUUID,
				"ip_address":  ip,
				"hw_address":  mac,
				"hostname":    xmlutil.AsString(m["hostname"]),
				"description": xmlutil.AsString(m["descr"]),
			}
			if cid != "" {
				item["client_id"] = cid
			}
			reservations = append(reservations, item)
			if ipInAnyRange(ip, scope.ranges) {
				inPool++
			}
		}
	}
	dnsmasq = dnsOnlyDnsmasq(pfsense, opt)
	if len(subnets) == 0 && dnsmasq == nil {
		return nil, nil
	}
	report.Stats.DhcpRanges = len(subnets)
	report.Stats.DhcpHosts = len(reservations)
	if len(subnets) > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"Mapped DHCP pools to Kea DHCPv4 (%d subnet(s), %d reservation(s)). Do not also enable dnsmasq DHCP on the same LAN.",
			len(subnets), len(reservations)))
		report.Notes = append(report.Notes,
			"Kea does not register DHCP hostnames in Unbound. Add host overrides if you need DNS names for reservations.")
	}
	if inPool > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"%d Kea reservation(s) sit inside the dynamic pool. OPNsense Kea expects reservations outside the pool; move them after import.",
			inPool))
	}
	if len(subnets) == 0 {
		return dnsmasq, nil
	}
	lifetime := keaLifetime(scopes)
	dhcp4 := map[string]any{
		"@_version": "1.0.6",
		"general": map[string]any{
			"enabled":        "1",
			"interfaces":     strings.Join(ifaces, ","),
			"fwrules":        "1",
			"valid_lifetime": lifetime,
		},
		"ha": map[string]any{"enabled": "0"},
		"subnets": map[string]any{
			"subnet4": subnets,
		},
	}
	if len(reservations) > 0 {
		dhcp4["reservations"] = map[string]any{"reservation": reservations}
	}
	return dnsmasq, map[string]any{"dhcp4": dhcp4}
}

type dhcpRange struct {
	from string
	to   string
}

type dhcpScope struct {
	iface  string
	cfg    map[string]any
	ranges []dhcpRange
	static []map[string]any
}

func appendDHCPRange(ranges []dhcpRange, from, to string) []dhcpRange {
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	if from == "" || to == "" {
		return ranges
	}
	for _, r := range ranges {
		if r.from == from && r.to == to {
			return ranges
		}
	}
	return append(ranges, dhcpRange{from: from, to: to})
}

func joinKeaPools(ranges []dhcpRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		if r.from != "" && r.to != "" {
			parts = append(parts, r.from+"-"+r.to)
		}
	}
	return strings.Join(parts, "\n")
}

func parseKeaPools(pools string) []dhcpRange {
	out := []dhcpRange{}
	for _, line := range strings.Split(pools, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.Index(line, "-")
		if i <= 0 {
			continue
		}
		out = appendDHCPRange(out, strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]))
	}
	return out
}

func ipInAnyRange(ip string, ranges []dhcpRange) bool {
	for _, r := range ranges {
		if ipInRange(ip, r.from, r.to) {
			return true
		}
	}
	return false
}

func collectDhcpd(pfsense map[string]any) []dhcpScope {
	dhcpd := xmlutil.Map(pfsense["dhcpd"])
	names := make([]string, 0, len(dhcpd))
	for iface, cfgRaw := range dhcpd {
		if xmlutil.Map(cfgRaw) == nil {
			continue
		}
		names = append(names, iface)
	}
	sort.Strings(names)
	ifaces := xmlutil.Map(pfsense["interfaces"])
	out := make([]dhcpScope, 0, len(names))
	for _, iface := range names {
		if xmlutil.Map(ifaces[iface]) == nil {
			continue
		}
		cfg := xmlutil.Map(dhcpd[iface])
		if xmlutil.AsString(cfg["enable"]) == "0" {
			continue
		}
		rng := xmlutil.Map(cfg["range"])
		scope := dhcpScope{
			iface:  iface,
			cfg:    cfg,
			ranges: appendDHCPRange(nil, xmlutil.AsString(rng["from"]), xmlutil.AsString(rng["to"])),
		}
		for _, sm := range xmlutil.AsArray(cfg["staticmap"]) {
			if m := xmlutil.Map(sm); m != nil {
				scope.static = append(scope.static, m)
			}
		}
		out = append(out, scope)
	}
	return out
}

func dnsOnlyDnsmasq(pfsense map[string]any, opt *Options) map[string]any {
	existing := xmlutil.Map(pfsense["dnsmasq"])
	if existing == nil {
		return nil
	}
	hosts := []any{}
	for _, host := range xmlutil.AsArray(existing["hosts"]) {
		h := xmlutil.Map(host)
		ip := xmlutil.AsString(h["ip"])
		name := xmlutil.AsString(h["host"])
		if ip == "" && name == "" && xmlutil.AsString(h["domain"]) == "" {
			continue
		}
		item := map[string]any{
			"host": name, "domain": xmlutil.AsString(h["domain"]),
			"ip": ip, "descr": xmlutil.AsString(h["descr"]),
		}
		if uuid := xmlutil.AsString(h["@_uuid"]); uuid != "" {
			item["@_uuid"] = uuid
		} else {
			item["@_uuid"] = nextUUID(opt)
		}
		hosts = append(hosts, item)
	}
	if len(hosts) == 0 && !xmlutil.FlagSet(existing["enable"]) {
		return nil
	}
	mapped := map[string]any{
		"port": orDefault(xmlutil.AsString(existing["port"]), "53053"),
	}
	if cleaned := strings.Join(validDhcpIfaces(pfsense, splitCSV(xmlutil.AsString(existing["interface"]))), ","); cleaned != "" {
		mapped["interface"] = cleaned
	}
	if len(hosts) > 0 {
		mapped["enable"] = "1"
		mapped["hosts"] = hosts
	} else if xmlutil.FlagSet(existing["enable"]) {
		mapped["enable"] = "1"
	}
	return mapped
}

func validDhcpIfaces(pfsense map[string]any, names []string) []string {
	ifaces := xmlutil.Map(pfsense["interfaces"])
	out := []string{}
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || name == "dhcpddata" || seen[name] {
			continue
		}
		if xmlutil.Map(ifaces[name]) == nil {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func ensureDnsmasqUUIDs(dns map[string]any, opt *Options) int {
	if dns == nil {
		return 0
	}
	n := 0
	for _, key := range []string{"dhcp_ranges", "hosts"} {
		items := xmlutil.AsArray(dns[key])
		if len(items) == 0 {
			continue
		}
		out := make([]any, 0, len(items))
		for _, raw := range items {
			m := xmlutil.Map(raw)
			if m == nil {
				out = append(out, raw)
				continue
			}
			if xmlutil.AsString(m["@_uuid"]) == "" {
				m["@_uuid"] = nextUUID(opt)
				n++
			}
			out = append(out, m)
		}
		dns[key] = out
	}
	return n
}

func interfaceCIDR(pfsense map[string]any, iface string) string {
	ifc := xmlutil.Map(xmlutil.Get(pfsense, "interfaces", iface))
	if ifc == nil {
		return ""
	}
	ip := net.ParseIP(xmlutil.AsString(ifc["ipaddr"]))
	if ip == nil || ip.To4() == nil {
		return ""
	}
	bits, err := strconv.Atoi(xmlutil.AsString(ifc["subnet"]))
	if err != nil || bits < 0 || bits > 32 {
		return ""
	}
	v4 := ip.To4()
	network := v4.Mask(net.CIDRMask(bits, 32))
	return fmt.Sprintf("%s/%d", network.String(), bits)
}

func interfaceDescr(pfsense map[string]any, iface string) string {
	return xmlutil.AsString(xmlutil.Get(pfsense, "interfaces", iface, "descr"))
}

func keaOptionData(pfsense map[string]any, cfg map[string]any) map[string]any {
	out := map[string]any{}
	if dns := csvField(cfg, "dnsserver"); dns != "" {
		out["domain_name_servers"] = dns
	}
	if gw := xmlutil.AsString(cfg["gateway"]); gw != "" {
		out["routers"] = gw
	}
	domain := xmlutil.AsString(cfg["domain"])
	if domain == "" {
		domain = xmlutil.AsString(xmlutil.Get(pfsense, "system", "domain"))
	}
	if domain != "" {
		out["domain_name"] = domain
	}
	if search := xmlutil.AsString(cfg["domainsearchlist"]); search != "" {
		out["domain_search"] = strings.ReplaceAll(search, " ", ",")
	}
	if tftp := xmlutil.AsString(cfg["tftp"]); tftp != "" {
		out["tftp_server_name"] = tftp
	}
	if file := xmlutil.AsString(cfg["filename"]); file != "" {
		out["boot_file_name"] = file
	}
	if ntp := csvField(cfg, "ntpserver"); ntp != "" {
		out["ntp_servers"] = ntp
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func keaLifetime(scopes []dhcpScope) string {
	for _, scope := range scopes {
		n, err := strconv.Atoi(strings.TrimSpace(xmlutil.AsString(scope.cfg["defaultleasetime"])))
		if err == nil && n > 0 {
			return strconv.Itoa(n)
		}
	}
	return "4000"
}

func csvField(node map[string]any, key string) string {
	parts := []string{}
	for _, raw := range xmlutil.AsArray(node[key]) {
		s := strings.TrimSpace(xmlutil.AsString(raw))
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ",")
}

func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", ":")
	s = strings.ReplaceAll(s, ".", ":")
	return s
}

func parseIPv4(s string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func ipInCIDR(ipStr, cidr string) bool {
	ip := parseIPv4(ipStr)
	_, network, err := net.ParseCIDR(cidr)
	if ip == nil || err != nil {
		return false
	}
	return network.Contains(ip)
}

func ipInRange(ip, from, to string) bool {
	addr := net.ParseIP(ip)
	a := net.ParseIP(from)
	b := net.ParseIP(to)
	if addr == nil || a == nil || b == nil || addr.To4() == nil || a.To4() == nil || b.To4() == nil {
		return false
	}
	v, lo, hi := addr.To4(), a.To4(), b.To4()
	return bytes.Compare(v, lo) >= 0 && bytes.Compare(v, hi) <= 0
}
