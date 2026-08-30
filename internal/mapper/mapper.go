package mapper

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

const (
	OpnSeries  = "26.7"
	OpnRelease = "26.7.3"
	PfRelease  = "2.7.0"
	PfRevision = "22.9"
)

// OpnTarget names the config layout: the whole 26.7 series, including 26.7.3.
func OpnTarget() string {
	return OpnSeries + " series (including " + OpnRelease + ")"
}

type Stats struct {
	FilterRules       int `json:"filterRules"`
	SkippedMatchRules int `json:"skippedMatchRules"`
	SkippedSeparators int `json:"skippedSeparators"`
	Aliases           int `json:"aliases"`
	Gateways          int `json:"gateways"`
	DhcpRanges        int `json:"dhcpRanges"`
	DhcpHosts         int `json:"dhcpHosts"`
	NatPortForwards   int `json:"natPortForwards"`
	Users             int `json:"users"`
	OpenvpnServers    int `json:"openvpnServers"`
	OpenvpnClients    int `json:"openvpnClients"`
	OpenvpnUsers      int `json:"openvpnUsers"`
	UserCerts         int `json:"userCerts"`
	Packages          int `json:"packages"`
}

type Notes struct {
	Notes   []string
	Skipped []string
	Stats   Stats
}

type Result struct {
	Root   map[string]any
	Report Notes
}

const (
	DhcpDnsmasq = "dnsmasq"
	DhcpKea     = "kea"
)

type Options struct {
	UUID        func() string
	DhcpBackend string // "dnsmasq" (default) or "kea"
}

// ParseDhcpBackend accepts UI/CLI values. Anything other than kea is dnsmasq.
func ParseDhcpBackend(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case DhcpKea, "kea-dhcp", "keadhcp":
		return DhcpKea
	default:
		return DhcpDnsmasq
	}
}

func dhcpBackend(opt *Options) string {
	if opt == nil {
		return DhcpDnsmasq
	}
	return ParseDhcpBackend(opt.DhcpBackend)
}

func nextUUID(opt *Options) string {
	if opt != nil && opt.UUID != nil {
		return opt.UUID()
	}
	return uuid.NewString()
}

var aliasTypes = map[string]struct{}{
	"host": {}, "network": {}, "port": {}, "url": {}, "urltable": {},
	"urljson": {}, "geoip": {}, "networkgroup": {}, "mac": {}, "asn": {},
	"dynipv6host": {}, "authgroup": {}, "external": {},
}

var filterActions = map[string]struct{}{"pass": {}, "block": {}, "reject": {}}

var stateTypes = map[string]string{
	"keep": "keep", "keep state": "keep", "sloppy": "sloppy", "sloppy state": "sloppy",
	"modulate": "modulate", "modulate state": "modulate", "synproxy": "synproxy",
	"synproxy state": "synproxy", "none": "none", "no state": "none",
}

var icmpTypes = map[string]struct{}{
	"echoreq": {}, "echorep": {}, "unreach": {}, "redir": {}, "routeradv": {},
	"routersol": {}, "timex": {}, "paramprob": {}, "timereq": {}, "timerep": {}, "photuris": {},
}

var interfaceKeep = map[string]struct{}{
	"enable": {}, "if": {}, "descr": {}, "ipaddr": {}, "subnet": {}, "gateway": {},
	"ipaddrv6": {}, "subnetv6": {}, "gatewayv6": {}, "blockpriv": {}, "blockbogons": {},
	"spoofmac": {}, "dhcphostname": {}, "dhcprejectfrom": {}, "media": {}, "mediaopt": {},
	"mtu": {}, "mss": {}, "track6-interface": {}, "track6-prefix-id": {},
	"dhcp6-ia-pd-len": {}, "dhcp6-ia-pd-enable": {}, "prefix-6rd": {}, "gateway-6rd": {},
	"alias-address": {}, "alias-subnet": {},
}

var dyndnsService = map[string]string{
	"noip": "no-ip", "noipfree": "no-ip", "dyndns": "dyndns", "dyndns2": "dyndns",
	"namecheap": "namecheap", "duckdns": "duck-dns", "cloudflare": "cloudflare",
	"godaddy": "godaddy", "freedns": "freedns", "google": "google", "he": "he-net",
	"henet": "he-net", "route53": "route53", "custom": "custom", "customv6": "custom",
	"gandi": "gandi-net", "strato": "strato", "ovh": "ovh", "dnsmadeeasy": "dnsmadeeasy",
}

var packageToPlugin = map[string]string{
	"openvpn-client-export":         "os-openvpn-client-export",
	"openvpn client export utility": "os-openvpn-client-export",
	"wireguard":                     "os-wireguard", "acme": "os-acme-client", "acme-client": "os-acme-client",
	"nmap": "os-nmap", "iperf": "os-iperf", "lldpd": "os-lldpd",
	"mdns-repeater": "os-mdns-repeater", "avahi": "os-mdns-repeater", "nut": "os-nut",
	"frr": "os-frr", "bind": "os-bind", "haproxy": "os-haproxy", "nginx": "os-nginx",
	"squid": "os-squid", "telegraf": "os-telegraf", "zabbix-agent": "os-zabbix-agent",
	"ntopng": "os-ntopng", "vnstat": "os-vnstat", "nrpe": "os-nrpe", "stunnel": "os-stunnel",
	"tinc": "os-tinc", "maltrail": "os-maltrail", "crowdsec": "os-crowdsec",
	"smartmontools": "os-smart", "wol": "os-wol", "dyndns": "os-ddclient",
	"rfc2136": "os-ddclient", "apcupsd": "os-apcupsd", "suricata": "os-suricata",
	"snort": "os-suricata",
}

func Map(input map[string]any, opt *Options) (*Result, error) {
	if xmlutil.Map(input["pfsense"]) != nil {
		return mapPfSense(input, opt)
	}
	if xmlutil.Map(input["opnsense"]) != nil {
		return mapOpnSense(input, opt)
	}
	return nil, fmt.Errorf("Incompatible file type\nMessage:  missing pfsense or opnsense root")
}

func mapPfSense(input map[string]any, opt *Options) (*Result, error) {
	pfsense := xmlutil.Map(input["pfsense"])
	if pfsense == nil {
		return nil, fmt.Errorf("Incompatible file type\nMessage:  pfsense object is null")
	}
	report := Notes{
		Notes: []string{
			fmt.Sprintf("Targeting OPNsense %s from pfSense %s (config revision %s).",
				OpnTarget(), PfRelease, orDefault(xmlutil.AsString(pfsense["version"]), PfRevision)),
		},
	}
	if ver := xmlutil.AsString(pfsense["version"]); ver != "" && ver != PfRevision {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"Source config revision is %s, not %s (pfSense %s). Mapping still runs; review the result.",
			ver, PfRevision, PfRelease))
	}

	rules := []any{}
	sequence := 1
	for _, raw := range collectFilterRules(pfsense) {
		rule := xmlutil.Map(raw)
		if rule == nil {
			continue
		}
		if _, hasSep := rule["separator"]; hasSep || (rule["type"] == nil && rule["proto"] == nil && rule["interface"] == nil && rule["if"] == nil && rule["source"] == nil && rule["dst"] == nil) {
			report.Stats.SkippedSeparators++
			continue
		}
		action := strings.ToLower(xmlutil.AsString(orVal(rule["type"], rule["action"])))
		if action == "match" {
			report.Stats.SkippedMatchRules++
			report.Skipped = append(report.Skipped, fmt.Sprintf(`Skipped filter rule "%s" (action=match is not supported on OPNsense).`, xmlutil.AsString(rule["descr"])))
			continue
		}
		if mapped := mapFilterRule(rule, sequence, opt); mapped != nil {
			rules = append(rules, mapped)
			sequence += 10
		}
	}
	report.Stats.FilterRules = len(rules)

	aliases := []any{}
	for _, raw := range xmlutil.AsArray(xmlutil.Get(pfsense, "aliases", "alias")) {
		if mapped := mapAlias(raw, opt); mapped != nil {
			aliases = append(aliases, mapped)
		}
	}
	report.Stats.Aliases = len(aliases)

	aliasBlock := map[string]any{}
	if len(aliases) > 0 {
		aliasBlock["alias"] = aliases
	}
	ruleBlock := map[string]any{}
	if len(rules) > 0 {
		ruleBlock["rule"] = rules
	}
	opnMVC := map[string]any{
		"Firewall": map[string]any{
			"Alias": map[string]any{"aliases": aliasBlock},
			"Filter": map[string]any{
				"rules":     ruleBlock,
				"snatrules": map[string]any{},
				"npt":       map[string]any{},
				"onetoone":  map[string]any{},
			},
		},
	}
	if gw := mapGateways(pfsense, opt, &report); gw != nil {
		opnMVC["Gateways"] = gw
	}
	dnsmasq, kea := mapDHCP(pfsense, opt, &report)
	vlans, vlanRenames := mapVlans(pfsense, opt, &report)
	openvpn := mapOpenVPN(pfsense, opt, &report)
	packages := mapPackages(pfsense, &report)
	dyndns := mapDynDNS(pfsense, opt, &report)
	ipsec, swanctl := mapIPsec(pfsense, opt, &report)
	cron := mapCron(pfsense, opt, &report)

	if !xmlutil.IsEmptySection(pfsense["shaper"]) || !xmlutil.IsEmptySection(pfsense["dnshaper"]) || !xmlutil.IsEmptySection(pfsense["ezshaper"]) {
		report.Notes = append(report.Notes, "Traffic shaping was copied as-is; OPNsense uses a different shaper. Review Firewall → Shaper.")
	}
	if !xmlutil.IsEmptySection(pfsense["captiveportal"]) {
		report.Notes = append(report.Notes, "Captive portal config was copied; confirm it under Services → Captive Portal after import.")
	}
	if pfsense["wireguard"] != nil || xmlutil.Get(pfsense, "installedpackages", "wireguard") != nil {
		report.Notes = append(report.Notes, "WireGuard config was copied; install os-wireguard on OPNsense if it is not already present.")
	}
	if openvpn != nil {
		opnMVC["OpenVPN"] = openvpn
	}
	if dyndns != nil {
		opnMVC["DynDNS"] = dyndns
	}
	if ipsec != nil {
		opnMVC["IPsec"] = ipsec
	}
	if swanctl != nil {
		opnMVC["Swanctl"] = swanctl
	}
	if cron != nil {
		opnMVC["cron"] = cron
	}
	if kea != nil {
		opnMVC["Kea"] = kea
	}

	opnsense := map[string]any{
		"theme":      "opnsense",
		"system":     mapSystem(pfsense, &report),
		"interfaces": mapInterfaces(pfsense, &report),
		"nat":        mapNAT(pfsense, &report),
		"filter":     map[string]any{},
		"unbound":    orVal(pfsense["unbound"], map[string]any{"enable": "1"}),
		"rrd":        map[string]any{"enable": ""},
		"ntpd": map[string]any{
			"prefer": "0.opnsense.pool.ntp.org",
			"ispool": "0.opnsense.pool.ntp.org 1.opnsense.pool.ntp.org 2.opnsense.pool.ntp.org 3.opnsense.pool.ntp.org",
		},
		"revision": map[string]any{
			"username":    "pf2opn",
			"time":        fmt.Sprintf("%v", float64(time.Now().UnixMilli())/1000),
			"description": fmt.Sprintf("Converted from pfSense %s by pf2opn for OPNsense %s", PfRelease, OpnTarget()),
		},
		"OPNsense": opnMVC,
	}
	if dnsmasq != nil {
		opnsense["dnsmasq"] = dnsmasq
	}
	if vlans != nil {
		opnsense["vlans"] = vlans
	}
	if packages != nil {
		opnsense["installedpackages"] = packages
	}

	passthrough := []string{
		"ca", "cert", "crl", "staticroutes", "virtualip", "bridges",
		"laggs", "gifs", "gres", "ppps", "wol", "syslog", "captiveportal",
		"shaper", "dnshaper", "load_balancer", "ifgroups", "qinqs", "wireless", "wireguard",
	}
	verified := map[string]struct{}{"ca": {}, "cert": {}, "crl": {}, "ppps": {}, "syslog": {}}
	for _, key := range passthrough {
		value := pfsense[key]
		if xmlutil.IsEmptySection(value) {
			continue
		}
		opnsense[key] = value
		if _, ok := verified[key]; !ok {
			report.Notes = append(report.Notes, fmt.Sprintf("Copied %s with minimal translation; verify after import.", key))
		}
	}
	groups := xmlutil.AsArray(xmlutil.Get(pfsense, "gateways", "gateway_group"))
	if len(groups) > 0 {
		opnsense["gateways"] = map[string]any{"gateway_group": groups}
		report.Notes = append(report.Notes, "Gateway groups were copied in legacy form; confirm them under System → Gateways.")
	}
	rewriteDeviceNames(opnsense, vlanRenames)

	return &Result{Root: map[string]any{"opnsense": opnsense}, Report: report}, nil
}

func BuildComment(report Notes) string {
	lines := []string{fmt.Sprintf("Generated by pf2opn for OPNsense %s", OpnTarget())}
	lines = append(lines, report.Notes...)
	lines = append(lines, report.Skipped...)
	lines = append(lines, fmt.Sprintf(
		"Mapped: %d filter rules, %d aliases, %d gateways, %d DHCP ranges, %d static maps, %d port forwards, %d OpenVPN users, %d packages.",
		report.Stats.FilterRules, report.Stats.Aliases, report.Stats.Gateways, report.Stats.DhcpRanges,
		report.Stats.DhcpHosts, report.Stats.NatPortForwards, report.Stats.OpenvpnUsers, report.Stats.Packages,
	))
	return strings.Join(lines, "\n")
}

func collectFilterRules(pfsense map[string]any) []any {
	out := xmlutil.AsArray(xmlutil.Get(pfsense, "filter", "rule"))
	out = append(out, xmlutil.AsArray(xmlutil.Get(pfsense, "firewall", "rule"))...)
	return out
}

func endpointNet(endpoint any) (net, not, port string) {
	m := xmlutil.Map(endpoint)
	if m == nil {
		return "any", "0", ""
	}
	not = xmlutil.Present01(m["not"])
	port = xmlutil.AsString(m["port"])
	if _, has := m["any"]; has {
		return "any", not, port
	}
	if xmlutil.AsString(m["network"]) != "" {
		return xmlutil.AsString(m["network"]), not, port
	}
	if xmlutil.AsString(m["address"]) != "" {
		return xmlutil.AsString(m["address"]), not, port
	}
	return "any", not, port
}

func mapProtocol(value any) string {
	proto := strings.TrimSpace(xmlutil.AsString(value))
	if proto == "" {
		return "any"
	}
	if proto == "tcp/udp" || proto == "TCP/UDP" {
		return "TCP/UDP"
	}
	if strings.ToLower(proto) == "tcp/udp" {
		return "TCP/UDP"
	}
	return proto
}

func mapStateType(value any) string {
	raw := strings.ToLower(strings.TrimSpace(xmlutil.AsString(value)))
	if mapped, ok := stateTypes[raw]; ok {
		return mapped
	}
	return "keep"
}

func mapFilterRule(rule map[string]any, sequence int, opt *Options) map[string]any {
	action := strings.ToLower(xmlutil.AsString(orVal(rule["type"], rule["action"], "pass")))
	if action == "match" {
		return nil
	}
	if action != "" {
		if _, ok := filterActions[action]; !ok {
			return nil
		}
	} else {
		action = "pass"
	}
	iface := xmlutil.LowerIdent(orVal(rule["interface"], rule["if"]))
	var srcNet, srcNot, srcPort, dstNet, dstNot, dstPort string
	if rule["source"] != nil {
		srcNet, srcNot, srcPort = endpointNet(rule["source"])
	} else {
		srcNet, srcNot, srcPort = orDefault(xmlutil.AsString(rule["src"]), "any"), "0", xmlutil.AsString(rule["srcport"])
	}
	if rule["destination"] != nil {
		dstNet, dstNot, dstPort = endpointNet(rule["destination"])
	} else {
		dstNet, dstNot, dstPort = orDefault(xmlutil.AsString(rule["dst"]), "any"), "0", xmlutil.AsString(rule["dstport"])
	}
	if srcNet == "" {
		srcNet = "any"
	}
	if dstNet == "" {
		dstNet = "any"
	}
	mapped := map[string]any{
		"@_uuid":           nextUUID(opt),
		"enabled":          ifThen(xmlutil.FlagSet(rule["disabled"]), "0", "1"),
		"statetype":        mapStateType(rule["statetype"]),
		"sequence":         fmt.Sprintf("%d", sequence),
		"action":           action,
		"quick":            "1",
		"interfacenot":     "0",
		"interface":        iface,
		"direction":        orDefault(xmlutil.AsString(rule["direction"]), "in"),
		"ipprotocol":       orDefault(xmlutil.AsString(rule["ipprotocol"]), "inet"),
		"protocol":         mapProtocol(orVal(rule["protocol"], rule["proto"])),
		"source_net":       srcNet,
		"source_not":       srcNot,
		"source_port":      srcPort,
		"destination_net":  dstNet,
		"destination_not":  dstNot,
		"destination_port": dstPort,
		"disablereplyto":   xmlutil.Present01(rule["disablereplyto"]),
		"log":              xmlutil.Present01(rule["log"]),
		"allowopts":        xmlutil.Present01(rule["allowopts"]),
		"nosync":           xmlutil.Present01(rule["nosync"]),
		"nopfsync":         xmlutil.Present01(rule["nopfsync"]),
		"tcpflags_any":     xmlutil.Present01(rule["tcpflags_any"]),
		"description":      xmlutil.AsString(orVal(rule["descr"], rule["description"])),
	}
	if xmlutil.FlagSet(rule["floating"]) {
		if rule["quick"] == nil {
			mapped["quick"] = "1"
		} else {
			mapped["quick"] = xmlutil.Present01(rule["quick"])
		}
	}
	if icmp := mapICMP(rule); icmp != "" {
		mapped["icmptype"] = icmp
	}
	if gw := xmlutil.AsString(rule["gateway"]); gw != "" {
		mapped["gateway"] = gw
	}
	return mapped
}

func mapICMP(rule map[string]any) string {
	raw := strings.TrimSpace(xmlutil.AsString(rule["icmptype"]))
	if raw == "" || raw == "any" {
		return ""
	}
	parts := strings.Split(raw, ",")
	kept := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if _, ok := icmpTypes[part]; ok {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, ",")
}

func mapAlias(raw any, opt *Options) map[string]any {
	alias := xmlutil.Map(raw)
	if alias == nil {
		return nil
	}
	name := xmlutil.AsString(alias["name"])
	if name == "" {
		return nil
	}
	typ := orDefault(xmlutil.AsString(alias["type"]), "host")
	if typ == "urltable_ports" {
		typ = "urltable"
	}
	if _, ok := aliasTypes[typ]; !ok {
		if strings.Contains(typ, "port") {
			typ = "port"
		} else {
			typ = "host"
		}
	}
	content := unique(append(append(xmlutil.SplitList(alias["address"]), xmlutil.SplitList(alias["content"])...), xmlutil.SplitList(alias["url"])...))
	uuid := xmlutil.AsString(alias["@_uuid"])
	if uuid == "" {
		uuid = nextUUID(opt)
	}
	enabled := "1"
	if alias["enabled"] != nil {
		enabled = xmlutil.Present01(alias["enabled"])
	}
	mapped := map[string]any{
		"@_uuid":      uuid,
		"enabled":     enabled,
		"name":        name,
		"type":        typ,
		"content":     strings.Join(content, "\n"),
		"description": xmlutil.AsString(orVal(alias["descr"], alias["description"])),
	}
	if xmlutil.AsString(alias["proto"]) != "" {
		mapped["proto"] = xmlutil.AsString(alias["proto"])
	}
	if xmlutil.AsString(alias["interface"]) != "" {
		mapped["interface"] = xmlutil.AsString(alias["interface"])
	}
	if xmlutil.FlagSet(alias["counters"]) {
		mapped["counters"] = "1"
	}
	if xmlutil.AsString(alias["updatefreq"]) != "" {
		mapped["updatefreq"] = xmlutil.AsString(alias["updatefreq"])
	}
	if xmlutil.AsString(alias["categories"]) != "" {
		mapped["categories"] = xmlutil.AsString(alias["categories"])
	}
	return mapped
}

func mapUser(raw any) map[string]any {
	user := xmlutil.Map(raw)
	if user == nil {
		return nil
	}
	name := xmlutil.AsString(user["name"])
	if name == "" {
		return nil
	}
	password := firstNonEmpty(
		xmlutil.AsString(user["password"]),
		xmlutil.AsString(user["bcrypt-hash"]),
		xmlutil.AsString(user["sha512-hash"]),
		xmlutil.AsString(user["md5-hash"]),
	)
	mapped := map[string]any{
		"name":      name,
		"descr":     xmlutil.AsString(user["descr"]),
		"scope":     orDefault(xmlutil.AsString(user["scope"]), "system"),
		"groupname": xmlutil.AsString(user["groupname"]),
		"uid":       xmlutil.AsString(user["uid"]),
		"password":  password,
	}
	priv := []any{}
	for _, p := range xmlutil.AsArray(user["priv"]) {
		if s := xmlutil.AsString(p); s != "" {
			priv = append(priv, s)
		}
	}
	if len(priv) == 1 {
		mapped["priv"] = priv[0]
	} else if len(priv) > 1 {
		mapped["priv"] = priv
	}
	if xmlutil.AsString(user["expires"]) != "" {
		mapped["expires"] = xmlutil.AsString(user["expires"])
	}
	if xmlutil.AsString(user["authorizedkeys"]) != "" {
		mapped["authorizedkeys"] = xmlutil.AsString(user["authorizedkeys"])
	}
	return mapped
}

func mapSystem(pfsense map[string]any, report *Notes) map[string]any {
	src := xmlutil.Map(pfsense["system"])
	if src == nil {
		src = map[string]any{}
	}
	users := []any{}
	for _, raw := range xmlutil.AsArray(src["user"]) {
		if u := mapUser(raw); u != nil {
			users = append(users, u)
		}
	}
	for _, raw := range users {
		u := xmlutil.Map(raw)
		if xmlutil.AsString(u["uid"]) == "0" && xmlutil.AsString(u["name"]) != "root" {
			report.Notes = append(report.Notes, fmt.Sprintf(
				`Renamed uid 0 user "%s" to "root" (OPNsense requires the root account).`, xmlutil.AsString(u["name"])))
			u["name"] = "root"
		}
	}
	groups := []any{}
	for _, raw := range xmlutil.AsArray(src["group"]) {
		g := xmlutil.Map(raw)
		if g == nil {
			continue
		}
		members := []any{}
		for _, m := range xmlutil.AsArray(g["member"]) {
			members = append(members, xmlutil.AsString(m))
		}
		priv := []any{}
		for _, p := range xmlutil.AsArray(g["priv"]) {
			priv = append(priv, xmlutil.AsString(p))
		}
		groups = append(groups, map[string]any{
			"name":        xmlutil.AsString(g["name"]),
			"description": xmlutil.AsString(g["description"]),
			"scope":       orDefault(xmlutil.AsString(g["scope"]), "system"),
			"gid":         xmlutil.AsString(g["gid"]),
			"member":      members,
			"priv":        priv,
		})
	}
	webgui := xmlutil.Map(src["webgui"])
	if webgui == nil {
		webgui = map[string]any{}
	}
	system := map[string]any{
		"optimization":         orDefault(xmlutil.AsString(src["optimization"]), "normal"),
		"hostname":             orDefault(xmlutil.AsString(src["hostname"]), "OPNsense"),
		"domain":               orDefault(xmlutil.AsString(src["domain"]), "internal"),
		"timezone":             orDefault(xmlutil.AsString(src["timezone"]), "Etc/UTC"),
		"language":             orDefault(xmlutil.AsString(src["language"]), "en_US"),
		"timeservers":          orDefault(xmlutil.AsString(src["timeservers"]), "0.opnsense.pool.ntp.org 1.opnsense.pool.ntp.org 2.opnsense.pool.ntp.org 3.opnsense.pool.ntp.org"),
		"dnsallowoverride":     xmlutil.Present01(src["dnsallowoverride"]),
		"user":                 users,
		"webgui":               map[string]any{"protocol": orDefault(xmlutil.AsString(webgui["protocol"]), "https")},
		"disablenatreflection": orDefault(xmlutil.AsString(src["disablenatreflection"]), "yes"),
		"bogons":               orVal(src["bogons"], map[string]any{"interval": "monthly"}),
	}
	if len(groups) > 0 {
		system["group"] = groups
	}
	if xmlutil.FlagSet(src["ipv6allow"]) {
		system["ipv6allow"] = "1"
	}
	if xmlutil.FlagSet(src["enablesshd"]) || src["ssh"] != nil {
		system["ssh"] = map[string]any{"group": "admins"}
	}
	dns := []any{}
	for _, d := range xmlutil.AsArray(src["dnsserver"]) {
		if s := xmlutil.AsString(d); s != "" {
			dns = append(dns, s)
		}
	}
	if len(dns) > 0 {
		system["dnsserver"] = dns
	}
	report.Stats.Users = len(users)
	return system
}

func mapInterfaces(pfsense map[string]any, report *Notes) map[string]any {
	src := xmlutil.Map(pfsense["interfaces"])
	mapped := map[string]any{}
	if src == nil {
		report.Skipped = append(report.Skipped, "No interface assignments found in the pfSense config.")
		return mapped
	}
	for name, value := range src {
		if strings.HasPrefix(name, "@_") {
			continue
		}
		var iface map[string]any
		if arr, ok := value.([]any); ok {
			if len(arr) == 0 {
				continue
			}
			iface = xmlutil.Map(arr[0])
			if len(arr) > 1 {
				report.Notes = append(report.Notes, fmt.Sprintf(`Interface "%s" had multiple blocks; kept the first. Check assignments on OPNsense.`, name))
			}
		} else {
			iface = xmlutil.Map(value)
		}
		if iface == nil {
			continue
		}
		clean := map[string]any{}
		for key, field := range iface {
			if _, ok := interfaceKeep[key]; !ok {
				continue
			}
			if key == "enable" {
				if xmlutil.FlagSet(field) || xmlutil.AsString(field) == "" {
					clean["enable"] = "1"
				} else {
					clean["enable"] = xmlutil.Present01(field)
				}
				continue
			}
			clean[key] = xmlutil.AsString(field)
		}
		if clean["enable"] == nil && (clean["if"] != nil || clean["ipaddr"] != nil) {
			clean["enable"] = "1"
		}
		mapped[name] = clean
	}
	if len(mapped) == 0 {
		report.Skipped = append(report.Skipped, "No interface assignments found in the pfSense config.")
	}
	return mapped
}

func mapGateways(pfsense map[string]any, opt *Options, report *Notes) map[string]any {
	items := xmlutil.AsArray(xmlutil.Get(pfsense, "gateways", "gateway_item"))
	if len(items) == 0 {
		return nil
	}
	mapped := []any{}
	for _, raw := range items {
		item := xmlutil.Map(raw)
		if item == nil {
			continue
		}
		weight := xmlutil.ClampInt(item["weight"], 1, 10, 1)
		if xmlutil.ClampInt(item["weight"], 1, 30, 1) > 10 {
			report.Notes = append(report.Notes, fmt.Sprintf(
				`Clamped gateway "%s" weight from %s to 10 (OPNsense max).`,
				xmlutil.AsString(item["name"]), xmlutil.AsString(item["weight"])))
		}
		monitor := "1"
		if item["monitor_disable"] != nil {
			monitor = xmlutil.Present01(item["monitor_disable"])
		}
		mapped = append(mapped, map[string]any{
			"@_uuid":          nextUUID(opt),
			"disabled":        xmlutil.Present01(item["disabled"]),
			"name":            xmlutil.AsString(item["name"]),
			"descr":           xmlutil.AsString(item["descr"]),
			"interface":       orDefault(xmlutil.LowerIdent(item["interface"]), "wan"),
			"ipprotocol":      orDefault(xmlutil.AsString(item["ipprotocol"]), "inet"),
			"gateway":         xmlutil.AsString(item["gateway"]),
			"defaultgw":       xmlutil.Present01(item["defaultgw"]),
			"monitor_disable": monitor,
			"priority":        fmt.Sprintf("%d", xmlutil.ClampInt(item["priority"], 0, 255, 255)),
			"weight":          fmt.Sprintf("%d", weight),
		})
	}
	report.Stats.Gateways = len(mapped)
	return map[string]any{"gateway_item": mapped}
}

func mapNAT(pfsense map[string]any, report *Notes) map[string]any {
	nat := xmlutil.Map(pfsense["nat"])
	if nat == nil {
		nat = map[string]any{}
	}
	outbound := xmlutil.Map(nat["outbound"])
	if outbound == nil {
		outbound = map[string]any{}
	}
	mode := orDefault(xmlutil.AsString(outbound["mode"]), "automatic")
	forwards := []any{}
	for _, raw := range xmlutil.AsArray(nat["rule"]) {
		rule := xmlutil.Map(raw)
		dest := map[string]any{}
		if d := xmlutil.Map(rule["destination"]); d != nil {
			for k, v := range d {
				dest[k] = v
			}
			if dest["address"] != nil {
				dest["address"] = strings.TrimSpace(xmlutil.AsString(dest["address"]))
			}
		}
		item := map[string]any{
			"protocol":    mapProtocol(rule["protocol"]),
			"interface":   xmlutil.LowerIdent(rule["interface"]),
			"ipprotocol":  orDefault(xmlutil.AsString(rule["ipprotocol"]), "inet"),
			"source":      orVal(rule["source"], map[string]any{"any": ""}),
			"destination": dest,
			"target":      strings.TrimSpace(xmlutil.AsString(rule["target"])),
			"local-port":  xmlutil.AsString(rule["local-port"]),
			"descr":       xmlutil.AsString(rule["descr"]),
		}
		if xmlutil.FlagSet(rule["disabled"]) {
			item["disabled"] = "1"
		}
		forwards = append(forwards, item)
	}
	report.Stats.NatPortForwards = len(forwards)
	if len(xmlutil.AsArray(outbound["rule"])) > 0 {
		report.Notes = append(report.Notes, "Custom outbound NAT rules were kept in legacy format. Use Firewall → NAT → Source NAT migration assistant on OPNsense 26.7 if prompted.")
	}
	mapped := map[string]any{"outbound": map[string]any{"mode": mode, "rule": xmlutil.AsArray(outbound["rule"])}}
	if len(forwards) > 0 {
		mapped["rule"] = forwards
	}
	return mapped
}

func mapDynDNS(pfsense map[string]any, opt *Options, report *Notes) map[string]any {
	rows := []any{}
	for _, raw := range xmlutil.AsArray(xmlutil.Get(pfsense, "dyndnses", "dyndns")) {
		row := xmlutil.Map(raw)
		if xmlutil.AsString(row["type"]) == "" && xmlutil.AsString(row["host"]) == "" && xmlutil.AsString(row["username"]) == "" {
			continue
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil
	}
	accounts := []any{}
	for _, raw := range rows {
		row := xmlutil.Map(raw)
		key := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(xmlutil.AsString(row["type"])), "")
		service := dyndnsService[key]
		if service == "" {
			service = strings.ToLower(xmlutil.AsString(row["type"]))
			if service == "" {
				service = "custom"
			}
			report.Notes = append(report.Notes, fmt.Sprintf(
				`DynDNS "%s" uses pfSense type "%s"; mapped as OPNsense service "%s". Confirm under Services → Dynamic DNS.`,
				firstNonEmpty(xmlutil.AsString(row["host"]), xmlutil.AsString(row["descr"]), service),
				xmlutil.AsString(row["type"]), service))
		}
		enabled := "0"
		if xmlutil.FlagSet(row["enable"]) {
			enabled = "1"
		}
		accounts = append(accounts, map[string]any{
			"@_uuid":      nextUUID(opt),
			"enabled":     enabled,
			"service":     service,
			"username":    xmlutil.AsString(row["username"]),
			"password":    xmlutil.AsString(row["password"]),
			"hostnames":   xmlutil.AsString(row["host"]),
			"description": xmlutil.AsString(row["descr"]),
			"interface":   orDefault(xmlutil.LowerIdent(orVal(row["interface"], row["requestif"])), "wan"),
			"checkip":     "if",
			"force_ssl":   "1",
		})
	}
	report.Notes = append(report.Notes, fmt.Sprintf("Mapped %d DynDNS account(s) to OPNsense DynDNS (os-ddclient). Install os-ddclient if it is not already present.", len(accounts)))
	return map[string]any{
		"general":  map[string]any{"enabled": "1", "verbose": "0", "interval": "300", "backend": "opnsense"},
		"accounts": map[string]any{"account": accounts},
	}
}

func decodeTLSKey(raw any) string {
	trimmed := strings.TrimSpace(xmlutil.AsString(raw))
	if trimmed == "" {
		return ""
	}
	if regexp.MustCompile(`(?i)BEGIN OpenVPN Static key`).MatchString(trimmed) {
		return strings.ReplaceAll(trimmed, "\r\n", "\n")
	}
	compact := regexp.MustCompile(`\s+`).ReplaceAllString(trimmed, "")
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err == nil {
		text := string(decoded)
		if regexp.MustCompile(`(?i)BEGIN OpenVPN Static key|OpenVPN static key`).MatchString(text) {
			return strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n"))
		}
	}
	return trimmed
}

func mapOvpnProto(value any) string {
	proto := regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(strings.ToLower(xmlutil.AsString(value)), "")
	switch proto {
	case "udp4", "udpipv4":
		return "udp4"
	case "udp6", "udpipv6":
		return "udp6"
	case "tcp4", "tcpipv4":
		return "tcp4"
	case "tcp6", "tcpipv6":
		return "tcp6"
	}
	if strings.HasPrefix(proto, "tcp") {
		return "tcp"
	}
	return "udp"
}

func mapOvpnDigest(value any) string {
	digest := strings.TrimSpace(xmlutil.AsString(value))
	if digest == "" {
		return ""
	}
	upper := regexp.MustCompile(`[^A-Z0-9-]`).ReplaceAllString(strings.ToUpper(digest), "")
	switch upper {
	case "SHA1", "SHA256", "SHA512", "SHA384", "SHA224":
		return upper
	}
	return digest
}

func mapOpenVPN(pfsense map[string]any, opt *Options, report *Notes) map[string]any {
	ovpn := xmlutil.Map(pfsense["openvpn"])
	if ovpn == nil {
		ovpn = map[string]any{}
	}
	servers := xmlutil.AsArray(ovpn["openvpn-server"])
	clients := xmlutil.AsArray(ovpn["openvpn-client"])
	cscs := []any{}
	for _, raw := range xmlutil.AsArray(ovpn["openvpn-csc"]) {
		if xmlutil.AsString(xmlutil.Map(raw)["common_name"]) != "" {
			cscs = append(cscs, raw)
		}
	}
	report.Stats.OpenvpnServers = len(servers)
	report.Stats.OpenvpnClients = len(clients)
	report.Stats.OpenvpnUsers = len(cscs)
	userCerts := 0
	for _, raw := range xmlutil.AsArray(pfsense["cert"]) {
		if strings.ToLower(xmlutil.AsString(xmlutil.Map(raw)["type"])) == "user" {
			userCerts++
		}
	}
	report.Stats.UserCerts = userCerts
	if len(servers)+len(clients)+len(cscs) == 0 {
		return nil
	}

	staticKeys := []any{}
	tlsByMaterial := map[string]string{}
	ensureKey := func(node map[string]any, label string) string {
		material := decodeTLSKey(node["tls"])
		if material == "" {
			return ""
		}
		if id, ok := tlsByMaterial[material]; ok {
			return id
		}
		id := nextUUID(opt)
		tlsType := strings.ToLower(xmlutil.AsString(node["tls_type"]))
		mode := "crypt"
		if tlsType == "auth" {
			mode = "auth"
		} else if strings.Contains(tlsType, "v2") {
			mode = "crypt-v2"
		}
		staticKeys = append(staticKeys, map[string]any{
			"@_uuid": id, "mode": mode, "key": material, "description": label + " TLS static key",
		})
		tlsByMaterial[material] = id
		return id
	}

	mapInstance := func(raw any, role string) map[string]any {
		node := xmlutil.Map(raw)
		id := nextUUID(opt)
		vpnid := orDefault(xmlutil.AsString(node["vpnid"]), fmt.Sprintf("%d", len(staticKeys)+1))
		label := orDefault(xmlutil.AsString(orVal(node["description"], node["descr"])), fmt.Sprintf("OpenVPN %s %s", role, vpnid))
		ncp := splitOvpnCiphers(orVal(node["ncp-ciphers"], node["ncp_ciphers"]))
		named := splitOvpnCiphers(orVal(node["data-ciphers"], node["data_ciphers"]))
		legacy := splitOvpnCiphers(node["crypto"])
		ciphers := uniqueNonEmpty(append(append(ncp, named...), legacy...))
		fallback := firstOvpnCipher(orVal(node["data-ciphers-fallback"], node["data_ciphers_fallback"]))
		if fallback == "" && len(legacy) == 1 {
			fallback = legacy[0]
		}
		if fallback == "" && len(ciphers) > 0 {
			fallback = ciphers[0]
		}
		flags := []string{}
		if xmlutil.YesFlag(node["client2client"]) {
			flags = append(flags, "client-to-client")
		}
		if xmlutil.YesFlag(node["passtos"]) {
			flags = append(flags, "passtos")
		}
		if xmlutil.YesFlag(node["duplicate_cn"]) || xmlutil.YesFlag(node["duplicate-cn"]) {
			flags = append(flags, "duplicate-cn")
		}
		if xmlutil.YesFlag(node["dynamic_ip"]) {
			flags = append(flags, "float")
		}
		if xmlutil.YesFlag(node["explicit_exit_notify"]) || xmlutil.YesFlag(node["explicit-exit-notify"]) {
			flags = append(flags, "explicit-exit-notify")
		}
		dev := "tun"
		if strings.ToLower(xmlutil.AsString(node["dev_mode"])) == "tap" {
			dev = "tap"
		}
		instance := map[string]any{
			"@_uuid":                  id,
			"vpnid":                   vpnid,
			"enabled":                 ifThen(xmlutil.FlagSet(node["disable"]), "0", "1"),
			"role":                    role,
			"dev_type":                dev,
			"verb":                    orDefault(xmlutil.AsString(node["verbosity_level"]), "3"),
			"proto":                   mapOvpnProto(node["protocol"]),
			"topology":                orDefault(xmlutil.AsString(node["topology"]), "subnet"),
			"description":             label,
			"remote_cert_tls":         "0",
			"verify_client_cert":      "require",
			"use_ocsp":                "0",
			"username_as_common_name": xmlutil.Present01(node["username_as_common_name"]),
			"strictusercn":            orDefault(xmlutil.AsString(node["strictusercn"]), "0"),
			"provision_exclusive":     "0",
			"register_dns":            xmlutil.Present01(node["register_dns"]),
		}
		if port := xmlutil.AsString(orVal(node["local_port"], node["port"])); port != "" {
			instance["port"] = port
		}
		if xmlutil.AsString(node["ipaddr"]) != "" {
			instance["local"] = xmlutil.AsString(node["ipaddr"])
		}
		if role == "server" && xmlutil.AsString(node["tunnel_network"]) != "" {
			instance["server"] = xmlutil.AsString(node["tunnel_network"])
		}
		if role == "server" && xmlutil.AsString(node["tunnel_networkv6"]) != "" {
			instance["server_ipv6"] = xmlutil.AsString(node["tunnel_networkv6"])
		}
		if xmlutil.AsString(node["local_network"]) != "" {
			instance["push_route"] = xmlutil.AsString(node["local_network"])
		}
		if xmlutil.AsString(node["remote_network"]) != "" {
			instance["route"] = xmlutil.AsString(node["remote_network"])
		}
		if xmlutil.AsString(node["certref"]) != "" {
			instance["cert"] = xmlutil.AsString(node["certref"])
		}
		if xmlutil.AsString(node["caref"]) != "" {
			instance["ca"] = xmlutil.AsString(node["caref"])
		}
		if xmlutil.AsString(node["crlref"]) != "" {
			instance["crl"] = xmlutil.AsString(node["crlref"])
		}
		if xmlutil.AsString(node["cert_depth"]) != "" {
			instance["cert_depth"] = xmlutil.AsString(node["cert_depth"])
		}
		if digest := mapOvpnDigest(node["digest"]); digest != "" {
			instance["auth"] = digest
		}
		if len(ciphers) > 0 {
			instance["data-ciphers"] = strings.Join(ciphers, ",")
		}
		if fallback != "" {
			instance["data-ciphers-fallback"] = fallback
		}
		if tls := ensureKey(node, label); tls != "" {
			instance["tls_key"] = tls
		}
		if len(flags) > 0 {
			instance["various_flags"] = strings.Join(flags, ",")
		}
		if xmlutil.YesFlag(node["gwredir"]) {
			instance["redirect_gateway"] = "def1"
		}
		if xmlutil.AsString(node["maxclients"]) != "" {
			instance["maxclients"] = xmlutil.AsString(node["maxclients"])
		}
		if xmlutil.AsString(node["authmode"]) != "" {
			instance["authmode"] = xmlutil.AsString(node["authmode"])
		}
		if role == "client" {
			host := xmlutil.AsString(orVal(node["server_addr"], node["remote"]))
			rport := xmlutil.AsString(orVal(node["server_port"], node["port"]))
			if host != "" {
				if rport != "" {
					instance["remote"] = host + " " + rport
				} else {
					instance["remote"] = host
				}
			}
		}
		if strings.ToLower(xmlutil.AsString(node["dev_mode"])) == "tap" {
			start, end := xmlutil.AsString(node["serverbridge_dhcp_start"]), xmlutil.AsString(node["serverbridge_dhcp_end"])
			if start != "" && end != "" {
				instance["bridge_pool"] = start + " " + end
			}
		}
		if c := xmlutil.AsString(node["compression"]); c != "" && c != "no" {
			instance["compress_migrate"] = "1"
			report.Notes = append(report.Notes, fmt.Sprintf(
				`OpenVPN "%s" used compression (%s); OPNsense 26.7 / OpenVPN 2.7 deprecates it. compress_migrate was enabled — test clients.`, label, c))
		}
		if xmlutil.AsString(node["custom_options"]) != "" {
			report.Notes = append(report.Notes, fmt.Sprintf(
				`OpenVPN "%s" had custom options that have no Instances field; review VPN → OpenVPN → Instances after import.`, label))
		}
		return instance
	}

	instances := []any{}
	for _, s := range servers {
		instances = append(instances, mapInstance(s, "server"))
	}
	for _, c := range clients {
		instances = append(instances, mapInstance(c, "client"))
	}
	serverUUIDs := []string{}
	for _, inst := range instances {
		m := xmlutil.Map(inst)
		if xmlutil.AsString(m["role"]) == "server" {
			serverUUIDs = append(serverUUIDs, xmlutil.AsString(m["@_uuid"]))
		}
	}
	overwrites := []any{}
	for _, raw := range cscs {
		csc := xmlutil.Map(raw)
		mapped := map[string]any{
			"@_uuid":      nextUUID(opt),
			"enabled":     "1",
			"common_name": xmlutil.AsString(csc["common_name"]),
			"block":       xmlutil.Present01(csc["block"]),
			"push_reset":  xmlutil.Present01(csc["push_reset"]),
			"description": xmlutil.AsString(orVal(csc["description"], csc["descr"])),
		}
		if len(serverUUIDs) > 0 {
			mapped["servers"] = strings.Join(serverUUIDs, ",")
		}
		if xmlutil.AsString(csc["tunnel_network"]) != "" {
			mapped["tunnel_network"] = xmlutil.AsString(csc["tunnel_network"])
		}
		if xmlutil.AsString(csc["tunnel_networkv6"]) != "" {
			mapped["tunnel_networkv6"] = xmlutil.AsString(csc["tunnel_networkv6"])
		}
		if xmlutil.AsString(csc["local_network"]) != "" {
			mapped["local_networks"] = xmlutil.AsString(csc["local_network"])
		}
		if xmlutil.AsString(csc["remote_network"]) != "" {
			mapped["remote_networks"] = xmlutil.AsString(csc["remote_network"])
		}
		if xmlutil.YesFlag(csc["gwredir"]) {
			mapped["redirect_gateway"] = "def1"
		}
		overwrites = append(overwrites, mapped)
	}
	report.Notes = append(report.Notes, fmt.Sprintf(
		"Mapped OpenVPN to OPNsense Instances (new): %d server(s), %d client(s), %d user overwrite(s), %d TLS static key(s)",
		len(servers), len(clients), len(cscs), len(staticKeys))+
		ifThen(userCerts > 0, fmt.Sprintf(", %d user certificate(s)", userCerts), "")+
		". Legacy VPN → OpenVPN → Servers is not written.")

	model := map[string]any{}
	if len(instances) > 0 {
		model["Instances"] = map[string]any{"Instance": instances}
	}
	if len(overwrites) > 0 {
		model["Overwrites"] = map[string]any{"Overwrite": overwrites}
	}
	if len(staticKeys) > 0 {
		model["StaticKeys"] = map[string]any{"StaticKey": staticKeys}
	}
	return model
}

func mapPackages(pfsense map[string]any, report *Notes) map[string]any {
	installed := xmlutil.Map(pfsense["installedpackages"])
	if installed == nil {
		return nil
	}
	names := []string{}
	for _, raw := range xmlutil.AsArray(installed["package"]) {
		p := xmlutil.Map(raw)
		name := firstNonEmpty(xmlutil.AsString(p["internal_name"]), xmlutil.AsString(p["name"]))
		if name != "" {
			names = append(names, name)
		}
	}
	extra := 0
	for k := range installed {
		if k != "package" {
			extra++
		}
	}
	report.Stats.Packages = len(names)
	if report.Stats.Packages == 0 {
		report.Stats.Packages = extra
	}
	plugins := unique([]string{})
	seen := map[string]struct{}{}
	for _, name := range names {
		if plug, ok := packageToPlugin[strings.ToLower(name)]; ok {
			if _, dup := seen[plug]; !dup {
				plugins = append(plugins, plug)
				seen[plug] = struct{}{}
			}
		}
	}
	if len(names) > 0 {
		msg := fmt.Sprintf("Copied pfSense package records (%s). These will not run on OPNsense; install matching plugins where they exist", strings.Join(names, ", "))
		if len(plugins) > 0 {
			msg += ": " + strings.Join(plugins, ", ")
		}
		report.Notes = append(report.Notes, msg+".")
	} else if extra > 0 {
		keys := []string{}
		for k := range installed {
			if k != "package" {
				keys = append(keys, k)
			}
		}
		report.Notes = append(report.Notes, fmt.Sprintf("Copied pfSense package configuration blocks (%s). Review after import; pfSense packages are not OPNsense plugins.", strings.Join(keys, ", ")))
	}
	return installed
}

func orVal(vals ...any) any {
	for _, v := range vals {
		if v != nil {
			if s, ok := v.(string); ok && s == "" {
				continue
			}
			return v
		}
	}
	return nil
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func ifThen[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func uniqueNonEmpty(in []string) []string {
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return unique(out)
}

func splitOvpnCiphers(value any) []string {
	return uniqueNonEmpty(regexp.MustCompile(`[:,\s]+`).Split(xmlutil.AsString(value), -1))
}

func firstOvpnCipher(value any) string {
	parts := splitOvpnCiphers(value)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
