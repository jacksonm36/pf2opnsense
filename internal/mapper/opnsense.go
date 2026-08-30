package mapper

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

func mapOpnSense(input map[string]any, opt *Options) (*Result, error) {
	src := xmlutil.Map(input["opnsense"])
	if src == nil {
		return nil, fmt.Errorf("Incompatible file type\nMessage:  opnsense object is null")
	}
	cfg := cloneMap(src)
	report := Notes{
		Notes: []string{
			fmt.Sprintf("Source is an OPNsense config. Preserving the document and remapping DHCP to %s for %s.",
				dhcpBackend(opt), OpnTarget()),
		},
	}
	applyOpnDHCP(cfg, opt, &report)
	if changed, _ := normalizeOpnVLANs(cfg, opt); changed {
		report.Notes = append(report.Notes, "Normalized VLAN devices to OPNsense vlan0.<tag> names and assigned UUIDs so Edit VLAN can load.")
	}
	if liftNestedSwanctl(cfg) {
		report.Notes = append(report.Notes, "Moved IPsec Connections from OPNsense/IPsec/Swanctl to OPNsense/Swanctl (26.7 model mount).")
	}
	stampRevision(cfg, fmt.Sprintf("OPNsense DHCP remapped to %s by pf2opn for %s", dhcpBackend(opt), OpnTarget()))
	return &Result{Root: map[string]any{"opnsense": cfg}, Report: report}, nil
}

// liftNestedSwanctl moves Connections from the wrong mount OPNsense/IPsec/Swanctl
// to OPNsense/Swanctl (//OPNsense/Swanctl in 26.7). Nested leftovers are always
// stripped so run_migrations.php cannot ignore a real sibling and keep an empty one.
func liftNestedSwanctl(cfg map[string]any) bool {
	mvc := xmlutil.Map(cfg["OPNsense"])
	if mvc == nil {
		return false
	}
	ipsec := xmlutil.Map(mvc["IPsec"])
	if ipsec == nil {
		return false
	}
	nested := xmlutil.Map(ipsec["Swanctl"])
	if nested == nil {
		return false
	}
	delete(ipsec, "Swanctl")
	mvc["IPsec"] = ipsec
	moved := swanctlHasConnections(nested) && !swanctlHasConnections(xmlutil.Map(mvc["Swanctl"]))
	if moved {
		mvc["Swanctl"] = nested
	}
	cfg["OPNsense"] = mvc
	return moved
}

func swanctlHasConnections(s map[string]any) bool {
	if s == nil {
		return false
	}
	return len(xmlutil.AsArray(xmlutil.Get(s, "Connections", "Connection"))) > 0 ||
		len(xmlutil.AsArray(xmlutil.Get(s, "children", "child"))) > 0
}

func stampRevision(cfg map[string]any, description string) {
	rev := xmlutil.Map(cfg["revision"])
	if rev == nil {
		rev = map[string]any{}
	} else {
		rev = cloneMap(rev)
	}
	rev["username"] = "pf2opn"
	rev["time"] = fmt.Sprintf("%v", float64(time.Now().UnixMilli())/1000)
	rev["description"] = description
	cfg["revision"] = rev
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneMap(t)
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return v
	}
}

func applyOpnDHCP(cfg map[string]any, opt *Options, report *Notes) {
	want := dhcpBackend(opt)
	dnsmaqScopes := collectDnsmasqScopes(cfg)
	keaScopes := collectKeaScopes(cfg)
	dhcpdScopes := collectDhcpd(cfg)

	switch want {
	case DhcpKea:
		if len(keaScopes) > 0 {
			extra := mergeDHCPScopesIntoKea(cfg, dnsmaqScopes, opt)
			writeOpnDnsmasq(cfg, stripDnsmasqDHCP(cloneMap(xmlutil.Map(cfg["dnsmasq"])), true))
			report.Stats.DhcpRanges = keaPoolCount(cfg)
			if extra > 0 {
				report.Notes = append(report.Notes, fmt.Sprintf(
					"Kept existing Kea DHCPv4, merged %d extra dnsmasq pool/reservation(s), and disabled dnsmasq DHCP.", extra))
			} else {
				report.Notes = append(report.Notes, "Kept existing Kea DHCPv4 and disabled dnsmasq DHCP.")
			}
		} else {
			scopes := dnsmaqScopes
			if len(scopes) == 0 {
				scopes = dhcpdScopes
			}
			dnsmasq, kea := buildKeaFromScopes(cfg, scopes, opt, report)
			writeOpnKea(cfg, kea)
			writeOpnDnsmasq(cfg, stripDnsmasqDHCP(dnsmasq, true))
			if kea != nil {
				report.Notes = append(report.Notes, "OPNsense DHCP backend is Kea. dnsmasq DHCP ranges were removed so both servers are not active.")
			} else {
				report.Notes = append(report.Notes, "No DHCP pools found to map to Kea. Other OPNsense settings were kept.")
				disableKeaDHCP(cfg)
			}
		}
	default:
		if len(dnsmaqScopes) > 0 {
			if extra := mergeDHCPScopesIntoDnsmasq(cfg, keaScopes, opt); extra > 0 {
				report.Notes = append(report.Notes, fmt.Sprintf(
					"Merged %d Kea-only pool/reservation(s) into dnsmasq DHCP.", extra))
			}
			disableKeaDHCP(cfg)
			report.Stats.DhcpRanges = len(xmlutil.AsArray(xmlutil.Get(cfg, "dnsmasq", "dhcp_ranges")))
			report.Notes = append(report.Notes, "Kept existing dnsmasq DHCP and disabled Kea DHCPv4.")
		} else if len(keaScopes) > 0 {
			writeOpnDnsmasq(cfg, buildDnsmasqFromScopes(cfg, keaScopes, opt, report))
			disableKeaDHCP(cfg)
			report.Notes = append(report.Notes, "Converted Kea DHCPv4 to dnsmasq DHCP. Kea was disabled so both servers are not active.")
		} else if len(dhcpdScopes) > 0 {
			writeOpnDnsmasq(cfg, buildDnsmasqFromScopes(cfg, dhcpdScopes, opt, report))
			disableKeaDHCP(cfg)
			report.Notes = append(report.Notes, "Mapped leftover ISC dhcpd to dnsmasq DHCP.")
		} else {
			disableKeaDHCP(cfg)
			report.Notes = append(report.Notes, "No DHCP pools found to map to dnsmasq. Other OPNsense settings were kept.")
		}
	}
	if xmlutil.Map(cfg["dhcpd"]) != nil {
		delete(cfg, "dhcpd")
		report.Notes = append(report.Notes, "Removed leftover ISC dhcpd from the OPNsense config (end-of-life on 26.7).")
	}
	sanitizeDnsmasqInterfaces(cfg)
	if n := ensureDnsmasqUUIDs(xmlutil.Map(cfg["dnsmasq"]), opt); n > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"Assigned UUIDs to %d dnsmasq host/range item(s) so Services → Dnsmasq → Hosts can edit and delete them.", n))
	}
}

func writeOpnDnsmasq(cfg map[string]any, dnsmasq map[string]any) {
	if dnsmasq == nil {
		delete(cfg, "dnsmasq")
		return
	}
	cfg["dnsmasq"] = dnsmasq
}

func writeOpnKea(cfg map[string]any, kea map[string]any) {
	mvc := xmlutil.Map(cfg["OPNsense"])
	if mvc == nil {
		mvc = map[string]any{}
		cfg["OPNsense"] = mvc
	} else {
		mvc = cloneMap(mvc)
		cfg["OPNsense"] = mvc
	}
	if kea == nil {
		if existing := xmlutil.Map(mvc["Kea"]); existing != nil {
			disableKeaIn(existing)
			mvc["Kea"] = existing
		}
		return
	}
	mvc["Kea"] = kea
}

func disableKeaDHCP(cfg map[string]any) {
	mvc := xmlutil.Map(cfg["OPNsense"])
	if mvc == nil {
		return
	}
	kea := xmlutil.Map(mvc["Kea"])
	if kea == nil {
		return
	}
	kea = cloneMap(kea)
	disableKeaIn(kea)
	mvc["Kea"] = kea
	cfg["OPNsense"] = mvc
}

func disableKeaIn(kea map[string]any) {
	dhcp4 := xmlutil.Map(kea["dhcp4"])
	if dhcp4 == nil {
		return
	}
	general := xmlutil.Map(dhcp4["general"])
	if general == nil {
		general = map[string]any{}
	} else {
		general = cloneMap(general)
	}
	general["enabled"] = "0"
	dhcp4["general"] = general
	delete(dhcp4, "subnets")
	delete(dhcp4, "reservations")
	kea["dhcp4"] = dhcp4
}

func stripDnsmasqDHCP(dnsmasq map[string]any, dropMACHosts bool) map[string]any {
	if dnsmasq == nil {
		return nil
	}
	out := cloneMap(dnsmasq)
	delete(out, "dhcp_ranges")
	delete(out, "dhcp")
	if dropMACHosts {
		kept := []any{}
		for _, raw := range xmlutil.AsArray(out["hosts"]) {
			h := xmlutil.Map(raw)
			if normalizeMAC(xmlutil.AsString(h["hwaddr"])) != "" {
				continue
			}
			if xmlutil.AsString(h["ip"]) == "" && xmlutil.AsString(h["host"]) == "" && xmlutil.AsString(h["domain"]) == "" {
				continue
			}
			kept = append(kept, h)
		}
		if len(kept) > 0 {
			out["hosts"] = kept
		} else {
			delete(out, "hosts")
		}
	}
	if len(xmlutil.AsArray(out["hosts"])) == 0 && !xmlutil.FlagSet(out["enable"]) {
		return nil
	}
	if len(xmlutil.AsArray(out["hosts"])) == 0 {
		delete(out, "enable")
		if len(out) == 0 || (len(out) == 1 && xmlutil.AsString(out["port"]) != "") {
			return nil
		}
	}
	return out
}

func collectDnsmasqScopes(cfg map[string]any) []dhcpScope {
	dns := xmlutil.Map(cfg["dnsmasq"])
	if dns == nil {
		return nil
	}
	byIface := map[string]*dhcpScope{}
	order := []string{}
	for _, raw := range xmlutil.AsArray(dns["dhcp_ranges"]) {
		r := xmlutil.Map(raw)
		from, to := xmlutil.AsString(r["start_addr"]), xmlutil.AsString(r["end_addr"])
		if from == "" || to == "" {
			continue
		}
		iface := xmlutil.LowerIdent(r["interface"])
		if iface == "" {
			iface = ifaceForIP(cfg, from)
		}
		if iface == "" {
			iface = firstCSV(xmlutil.AsString(dns["interface"]))
		}
		if iface == "" {
			iface = "lan"
		}
		sc := byIface[iface]
		if sc == nil {
			sc = &dhcpScope{iface: iface, cfg: map[string]any{}}
			byIface[iface] = sc
			order = append(order, iface)
		}
		sc.ranges = appendDHCPRange(sc.ranges, from, to)
	}
	for _, raw := range xmlutil.AsArray(dns["hosts"]) {
		h := xmlutil.Map(raw)
		ip, mac := xmlutil.AsString(h["ip"]), normalizeMAC(xmlutil.AsString(h["hwaddr"]))
		if ip == "" && mac == "" {
			continue
		}
		if mac == "" {
			continue
		}
		iface := ifaceForIP(cfg, ip)
		if iface == "" {
			iface = firstCSV(xmlutil.AsString(dns["interface"]))
		}
		if iface == "" {
			iface = "lan"
		}
		sc := byIface[iface]
		if sc == nil {
			sc = &dhcpScope{iface: iface, cfg: map[string]any{}}
			byIface[iface] = sc
			order = append(order, iface)
		}
		sc.static = append(sc.static, map[string]any{
			"ipaddr": ip, "mac": mac, "hostname": xmlutil.AsString(h["host"]), "descr": xmlutil.AsString(h["descr"]),
		})
	}
	out := make([]dhcpScope, 0, len(order))
	for _, iface := range order {
		out = append(out, *byIface[iface])
	}
	return out
}

func collectKeaScopes(cfg map[string]any) []dhcpScope {
	dhcp4 := xmlutil.Map(xmlutil.Get(cfg, "OPNsense", "Kea", "dhcp4"))
	if dhcp4 == nil {
		return nil
	}
	if xmlutil.AsString(xmlutil.Get(dhcp4, "general", "enabled")) == "0" {
		return nil
	}
	subs := xmlutil.AsArray(xmlutil.Get(dhcp4, "subnets", "subnet4"))
	if len(subs) == 0 {
		return nil
	}
	resBySubnet := map[string][]map[string]any{}
	for _, raw := range xmlutil.AsArray(xmlutil.Get(dhcp4, "reservations", "reservation")) {
		r := xmlutil.Map(raw)
		sid := xmlutil.AsString(r["subnet"])
		resBySubnet[sid] = append(resBySubnet[sid], r)
	}
	fallbackIface := firstCSV(xmlutil.AsString(xmlutil.Get(dhcp4, "general", "interfaces")))
	out := []dhcpScope{}
	for _, raw := range subs {
		sub := xmlutil.Map(raw)
		cidr := xmlutil.AsString(sub["subnet"])
		uuid := xmlutil.AsString(sub["@_uuid"])
		iface := ifaceForCIDR(cfg, cidr)
		if iface == "" {
			iface = xmlutil.LowerIdent(sub["description"])
		}
		if xmlutil.Map(xmlutil.Get(cfg, "interfaces", iface)) == nil {
			iface = fallbackIface
		}
		if iface == "" {
			iface = "lan"
		}
		sc := dhcpScope{iface: iface, cfg: map[string]any{}, ranges: parseKeaPools(xmlutil.AsString(sub["pools"]))}
		if dns := xmlutil.AsString(xmlutil.Get(sub, "option_data", "domain_name_servers")); dns != "" {
			sc.cfg["dnsserver"] = strings.ReplaceAll(dns, ",", "\n")
		}
		for _, r := range resBySubnet[uuid] {
			sc.static = append(sc.static, map[string]any{
				"ipaddr":   xmlutil.AsString(r["ip_address"]),
				"mac":      normalizeMAC(xmlutil.AsString(r["hw_address"])),
				"hostname": xmlutil.AsString(r["hostname"]),
				"descr":    xmlutil.AsString(r["description"]),
				"cid":      xmlutil.AsString(r["client_id"]),
			})
		}
		out = append(out, sc)
	}
	return out
}

func mergeDHCPScopesIntoKea(cfg map[string]any, extra []dhcpScope, opt *Options) int {
	if len(extra) == 0 {
		return 0
	}
	mvc := xmlutil.Map(cfg["OPNsense"])
	if mvc == nil {
		return 0
	}
	kea := xmlutil.Map(mvc["Kea"])
	if kea == nil {
		return 0
	}
	dhcp4 := xmlutil.Map(kea["dhcp4"])
	if dhcp4 == nil {
		return 0
	}
	subnets := xmlutil.AsArray(xmlutil.Get(dhcp4, "subnets", "subnet4"))
	reservations := xmlutil.AsArray(xmlutil.Get(dhcp4, "reservations", "reservation"))
	cidrToIdx := map[string]int{}
	ifaceToIdx := map[string]int{}
	for i, raw := range subnets {
		sub := xmlutil.Map(raw)
		cidr := xmlutil.AsString(sub["subnet"])
		cidrToIdx[cidr] = i
		if name := ifaceForCIDR(cfg, cidr); name != "" {
			ifaceToIdx[name] = i
		}
	}
	seenRes := map[string]bool{}
	for _, raw := range reservations {
		r := xmlutil.Map(raw)
		seenRes[normalizeMAC(xmlutil.AsString(r["hw_address"]))+"|"+xmlutil.AsString(r["ip_address"])] = true
	}
	general := xmlutil.Map(dhcp4["general"])
	if general == nil {
		general = map[string]any{}
	} else {
		general = cloneMap(general)
	}
	ifaces := splitCSV(xmlutil.AsString(general["interfaces"]))
	ifaceSet := map[string]bool{}
	for _, n := range ifaces {
		ifaceSet[n] = true
	}
	added := 0
	for _, sc := range extra {
		idx, ok := ifaceToIdx[sc.iface]
		cidr := interfaceCIDR(cfg, sc.iface)
		if !ok {
			if j, found := cidrToIdx[cidr]; found {
				idx, ok = j, true
			}
		}
		if !ok {
			if cidr == "" {
				continue
			}
			sub := map[string]any{
				"@_uuid":                  nextUUID(opt),
				"subnet":                  cidr,
				"description":             orDefault(interfaceDescr(cfg, sc.iface), strings.ToUpper(sc.iface)),
				"option_data_autocollect": "1",
				"pools":                   joinKeaPools(sc.ranges),
			}
			subnets = append(subnets, sub)
			idx = len(subnets) - 1
			cidrToIdx[cidr] = idx
			ifaceToIdx[sc.iface] = idx
			if sc.iface != "" && !ifaceSet[sc.iface] {
				ifaces = append(ifaces, sc.iface)
				ifaceSet[sc.iface] = true
			}
			if n := len(sc.ranges); n > 0 {
				added += n
			} else {
				added++
			}
		} else {
			sub := xmlutil.Map(subnets[idx])
			pools := parseKeaPools(xmlutil.AsString(sub["pools"]))
			before := len(pools)
			for _, r := range sc.ranges {
				pools = appendDHCPRange(pools, r.from, r.to)
			}
			if len(pools) > before {
				added += len(pools) - before
				sub["pools"] = joinKeaPools(pools)
				subnets[idx] = sub
			}
		}
		sid := xmlutil.AsString(xmlutil.Map(subnets[idx])["@_uuid"])
		for _, s := range sc.static {
			ip := xmlutil.AsString(s["ipaddr"])
			mac := normalizeMAC(xmlutil.AsString(s["mac"]))
			cid := strings.TrimSpace(xmlutil.AsString(s["cid"]))
			if mac == "" && cid == "" {
				continue
			}
			key := mac + "|" + ip
			if seenRes[key] {
				continue
			}
			item := map[string]any{
				"@_uuid":      nextUUID(opt),
				"subnet":      sid,
				"ip_address":  ip,
				"hw_address":  mac,
				"hostname":    xmlutil.AsString(s["hostname"]),
				"description": xmlutil.AsString(s["descr"]),
			}
			if cid != "" {
				item["client_id"] = cid
			}
			reservations = append(reservations, item)
			seenRes[key] = true
			added++
		}
	}
	if added == 0 {
		return 0
	}
	dhcp4["subnets"] = map[string]any{"subnet4": subnets}
	if len(reservations) > 0 {
		dhcp4["reservations"] = map[string]any{"reservation": reservations}
	}
	general["interfaces"] = strings.Join(ifaces, ",")
	dhcp4["general"] = general
	kea["dhcp4"] = dhcp4
	mvc["Kea"] = kea
	cfg["OPNsense"] = mvc
	return added
}

func mergeDHCPScopesIntoDnsmasq(cfg map[string]any, extra []dhcpScope, opt *Options) int {
	if len(extra) == 0 {
		return 0
	}
	dns := xmlutil.Map(cfg["dnsmasq"])
	if dns == nil {
		dns = map[string]any{}
	} else {
		dns = cloneMap(dns)
	}
	ranges := xmlutil.AsArray(dns["dhcp_ranges"])
	hosts := xmlutil.AsArray(dns["hosts"])
	seenR := map[string]bool{}
	for _, raw := range ranges {
		r := xmlutil.Map(raw)
		seenR[xmlutil.AsString(r["start_addr"])+"-"+xmlutil.AsString(r["end_addr"])] = true
	}
	seenH := map[string]bool{}
	for _, raw := range hosts {
		h := xmlutil.Map(raw)
		seenH[normalizeMAC(xmlutil.AsString(h["hwaddr"]))+"|"+xmlutil.AsString(h["ip"])] = true
	}
	ifaces := splitCSV(xmlutil.AsString(dns["interface"]))
	ifaceSet := map[string]bool{}
	for _, n := range ifaces {
		ifaceSet[n] = true
	}
	added := 0
	for _, sc := range extra {
		if sc.iface != "" && !ifaceSet[sc.iface] {
			ifaces = append(ifaces, sc.iface)
			ifaceSet[sc.iface] = true
		}
		for _, r := range sc.ranges {
			key := r.from + "-" + r.to
			if seenR[key] {
				continue
			}
			ranges = append(ranges, map[string]any{
				"@_uuid": nextUUID(opt), "interface": sc.iface, "start_addr": r.from, "end_addr": r.to,
			})
			seenR[key] = true
			added++
		}
		for _, s := range sc.static {
			ip, mac := xmlutil.AsString(s["ipaddr"]), normalizeMAC(xmlutil.AsString(s["mac"]))
			key := mac + "|" + ip
			if (ip == "" && mac == "") || seenH[key] {
				continue
			}
			hosts = append(hosts, map[string]any{
				"@_uuid": nextUUID(opt),
				"host":   xmlutil.AsString(s["hostname"]), "ip": ip, "hwaddr": mac, "descr": xmlutil.AsString(s["descr"]),
			})
			seenH[key] = true
			added++
		}
	}
	if added == 0 {
		return 0
	}
	if len(ranges) > 0 {
		dns["dhcp_ranges"] = ranges
		dns["enable"] = "1"
		dns["dhcp"] = map[string]any{"enable_ra": "1"}
	}
	if len(hosts) > 0 {
		dns["hosts"] = hosts
		dns["enable"] = "1"
	}
	if len(ifaces) > 0 {
		dns["interface"] = strings.Join(ifaces, ",")
	}
	cfg["dnsmasq"] = dns
	return added
}

func keaPoolCount(cfg map[string]any) int {
	n := 0
	for _, sc := range collectKeaScopes(cfg) {
		n += len(sc.ranges)
	}
	return n
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func buildKeaFromScopes(cfg map[string]any, scopes []dhcpScope, opt *Options, report *Notes) (dnsmasq, kea map[string]any) {
	if len(scopes) == 0 {
		return dnsOnlyFromOpn(cfg), nil
	}
	return keaFromScopes(cfg, scopes, opt, report)
}

func buildDnsmasqFromScopes(cfg map[string]any, scopes []dhcpScope, opt *Options, report *Notes) map[string]any {
	fake := map[string]any{
		"dnsmasq":    xmlutil.Get(cfg, "dnsmasq"),
		"interfaces": xmlutil.Get(cfg, "interfaces"),
		"system":     xmlutil.Get(cfg, "system"),
	}
	mapped := dnsmasqFromScopes(fake, scopes, opt, report)
	if mapped == nil {
		return dnsOnlyFromOpn(cfg)
	}
	return mapped
}

func sanitizeDnsmasqInterfaces(cfg map[string]any) {
	dns := xmlutil.Map(cfg["dnsmasq"])
	if dns == nil {
		return
	}
	cleaned := validDhcpIfaces(cfg, splitCSV(xmlutil.AsString(dns["interface"])))
	if len(cleaned) > 0 {
		dns["interface"] = strings.Join(cleaned, ",")
	} else {
		delete(dns, "interface")
	}
}

func dnsOnlyFromOpn(cfg map[string]any) map[string]any {
	return stripDnsmasqDHCP(cloneMap(xmlutil.Map(cfg["dnsmasq"])), false)
}

func ifaceForCIDR(cfg map[string]any, cidr string) string {
	if cidr == "" {
		return ""
	}
	ifaces := xmlutil.Map(cfg["interfaces"])
	for _, name := range sortedKeys(ifaces) {
		if interfaceCIDR(cfg, name) == cidr {
			return name
		}
	}
	return ""
}

func ifaceForIP(cfg map[string]any, ip string) string {
	addr := parseIPv4(ip)
	if addr == nil {
		return ""
	}
	ifaces := xmlutil.Map(cfg["interfaces"])
	for _, name := range sortedKeys(ifaces) {
		cidr := interfaceCIDR(cfg, name)
		if cidr != "" && ipInCIDR(ip, cidr) {
			return name
		}
	}
	return ""
}

func firstCSV(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(s, ",")[0])
}

func sortedKeys(m map[string]any) []string {
	names := make([]string, 0, len(m))
	for k, v := range m {
		if xmlutil.Map(v) == nil {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
