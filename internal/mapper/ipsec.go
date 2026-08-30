package mapper

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

var dhGroups = map[string]string{
	"1": "modp768", "2": "modp1024", "5": "modp1536", "14": "modp2048",
	"15": "modp3072", "16": "modp4096", "17": "modp6144", "18": "modp8192",
	"19": "ecp256", "20": "ecp384", "21": "ecp521", "22": "modp1024s160",
	"23": "modp2048s224", "24": "modp2048s256", "28": "ecp256bp",
	"29": "ecp384bp", "30": "ecp512bp", "31": "x25519", "32": "x448",
}

func mapIPsec(pfsense map[string]any, opt *Options, report *Notes) (ipsec, swanctl map[string]any) {
	src := xmlutil.Map(pfsense["ipsec"])
	if src == nil {
		return nil, nil
	}

	phase1s := usablePhase1(src)
	phase2s := xmlutil.AsArray(src["phase2"])
	mobile := usableMobileKeys(src)
	if len(phase1s)+len(mobile) == 0 {
		return nil, nil
	}
	ifaces := xmlutil.Map(pfsense["interfaces"])

	ikeToUUID := map[string]string{}
	reservedIke := reservedIkeIDs(phase1s)
	claimedIke := map[string]struct{}{}
	responderOnly := map[string]bool{}
	connections := []any{}
	locals := []any{}
	remotes := []any{}
	psks := []any{}
	children := []any{}
	spds := []any{}
	certNotes := 0

	for _, raw := range phase1s {
		p1 := xmlutil.Map(raw)
		ikeid := nextIkeID(xmlutil.AsString(p1["ikeid"]), reservedIke, claimedIke)
		connUUID := nextUUID(opt)
		ikeToUUID[ikeid] = connUUID
		responderOnly[ikeid] = xmlutil.FlagSet(p1["responderonly"])
		descr := orDefault(xmlutil.AsString(p1["descr"]), "IKE "+ikeid)
		remoteGW := xmlutil.AsString(p1["remote-gateway"])
		auth := strings.ToLower(xmlutil.AsString(p1["authentication_method"]))
		localAddr := interfaceBindAddr(p1["interface"], ifaces)
		proposals := p1Proposals(p1)

		conn := map[string]any{
			"@_uuid":       connUUID,
			"enabled":      ifThen(xmlutil.FlagSet(p1["disabled"]), "0", "1"),
			"proposals":    proposals,
			"unique":       "no",
			"aggressive":   ifThen(xmlutil.LowerIdent(p1["mode"]) == "aggressive", "1", "0"),
			"version":      ikeVersion(p1["iketype"]),
			"mobike":       mobikeFlag(p1["mobike"]),
			"local_addrs":  localAddr,
			"remote_addrs": remoteGW,
			// OPNsense encap means "force UDP encapsulation"; pfSense "on" only auto-detects NAT.
			"encap":        ifThen(strings.EqualFold(xmlutil.AsString(p1["nat_traversal"]), "force"), "1", "0"),
			"rekey_time":   xmlutil.AsString(p1["lifetime"]),
			"dpd_delay":    validPositiveInt(p1["dpd_delay"]),
			"dpd_timeout":  dpdTimeout(p1["dpd_delay"], p1["dpd_maxfail"]),
			"send_certreq": "1",
			"description":  descr,
		}
		connections = append(connections, conn)
		if weakProposal(proposals) {
			report.Notes = append(report.Notes, fmt.Sprintf(
				`IPsec connection "%s" imported with IKE proposal %s. SHA-1 and/or DH ≤ modp2048 are weak on OPNsense %s; coordinate an upgrade (e.g. aes256-sha256-modp3072) with the remote peer.`,
				descr, proposals, OpnTarget()))
		}

		localID := identValue(p1["myid_type"], p1["myid_data"], "")
		remoteID := identValue(p1["peerid_type"], p1["peerid_data"], remoteGW)
		authKind := "psk"
		if strings.Contains(auth, "rsa") || strings.Contains(auth, "cert") {
			authKind = "pubkey"
			certNotes++
		}

		local := map[string]any{
			"@_uuid":      nextUUID(opt),
			"enabled":     "1",
			"connection":  connUUID,
			"round":       "0",
			"auth":        authKind,
			"id":          localID,
			"description": descr + " local",
		}
		if authKind == "pubkey" && xmlutil.AsString(p1["certref"]) != "" {
			local["certs"] = xmlutil.AsString(p1["certref"])
		}
		locals = append(locals, local)

		remote := map[string]any{
			"@_uuid":      nextUUID(opt),
			"enabled":     "1",
			"connection":  connUUID,
			"round":       "0",
			"auth":        authKind,
			"id":          remoteID,
			"description": descr + " remote",
		}
		if authKind == "pubkey" && xmlutil.AsString(p1["caref"]) != "" {
			remote["cacerts"] = xmlutil.AsString(p1["caref"])
		}
		remotes = append(remotes, remote)

		if authKind == "psk" {
			psk := xmlutil.AsString(p1["pre-shared-key"])
			if psk != "" {
				// OPNsense writes "id-0 = <ident>" into swanctl secrets, so an empty
				// ident silently produces a key strongSwan can never match.
				ident := pskIdent(localID, localAddr)
				if ident == "%any" && localID == "" && localAddr == "" {
					report.Notes = append(report.Notes, fmt.Sprintf(
						`IPsec pre-shared key for "%s" had no local identifier (pfSense used "My IP address" on a dynamic WAN). It was stored as %%any so strongSwan can match the key; set a real local identifier under VPN → IPsec → Pre-Shared Keys if the peer requires one.`,
						descr))
				}
				psks = append(psks, map[string]any{
					"@_uuid":       nextUUID(opt),
					"ident":        ident,
					"remote_ident": orDefault(remoteID, remoteGW),
					"keyType":      "PSK",
					"Key":          psk,
					"description":  descr,
				})
			}
		}
	}

	for _, raw := range phase2s {
		p2 := xmlutil.Map(raw)
		ikeid := xmlutil.AsString(p2["ikeid"])
		parent, ok := ikeToUUID[ikeid]
		if !ok {
			continue
		}
		childUUID := nextUUID(opt)
		descr := orDefault(xmlutil.AsString(p2["descr"]), "Child "+xmlutil.AsString(p2["uniqid"]))
		esp := p2Proposals(p2)
		rawMode := xmlutil.LowerIdent(p2["mode"])
		mode := childMode(rawMode)
		reqid := childReqid(p2["reqid"])
		if raw := strings.TrimSpace(xmlutil.AsString(p2["reqid"])); raw != "" && reqid == "" {
			report.Notes = append(report.Notes, fmt.Sprintf(
				`IPsec child "%s" had reqid %q, which is outside 1–65535 and was dropped.`,
				descr, raw))
		}
		child := map[string]any{
			"@_uuid":        childUUID,
			"enabled":       ifThen(xmlutil.FlagSet(p2["disabled"]), "0", "1"),
			"connection":    parent,
			"reqid":         reqid,
			"esp_proposals": esp,
			"sha256_96":     "0",
			"start_action":  ifThen(responderOnly[ikeid], "none", "start"),
			"close_action":  "none",
			"dpd_action":    "clear",
			"mode":          mode,
			"policies":      ifThen(rawMode == "vti", "0", "1"),
			"local_ts":      trafficSelector(p2["localid"], ifaces, rawMode),
			"remote_ts":     trafficSelector(p2["remoteid"], ifaces, rawMode),
			"rekey_time":    xmlutil.AsString(p2["lifetime"]),
			"description":   descr,
		}
		if weakProposal(esp) {
			report.Notes = append(report.Notes, fmt.Sprintf(
				`IPsec child "%s" imported with ESP %s. SHA-1 and/or DH ≤ modp2048 are weak on OPNsense %s; coordinate an upgrade (e.g. aes256-sha256-modp3072) with the remote peer.`,
				descr, esp, OpnTarget()))
		}
		if rawMode != "" && rawMode != mode {
			report.Notes = append(report.Notes, fmt.Sprintf(
				`IPsec child "%s" used pfSense mode "%s", which OPNsense does not offer; it was imported as "%s". Route-based (VTI) tunnels need a VTI entry under VPN → IPsec → Virtual Tunnel Interfaces.`,
				descr, rawMode, mode))
		}
		if proto := xmlutil.LowerIdent(p2["protocol"]); proto == "ah" {
			report.Notes = append(report.Notes, fmt.Sprintf(
				`IPsec child "%s" used AH. OPNsense child SAs only carry ESP proposals, so it was imported as ESP %s; rebuild it as an AH tunnel if the peer requires AH.`,
				descr, esp))
		}
		children = append(children, child)
		if spd := xmlutil.AsString(p2["spd"]); spd != "" {
			spds = append(spds, map[string]any{
				"@_uuid":           nextUUID(opt),
				"enabled":          "1",
				"protocol":         orDefault(xmlutil.AsString(p2["protocol"]), "esp"),
				"connection_child": childUUID,
				"source":           spd,
			})
		}
	}

	for _, raw := range mobile {
		k := xmlutil.Map(raw)
		ident := orDefault(xmlutil.AsString(k["ident"]), "%any")
		psks = append(psks, map[string]any{
			"@_uuid":       nextUUID(opt),
			"ident":        ident,
			"remote_ident": "",
			"keyType":      "PSK",
			"Key":          xmlutil.AsString(k["pre-shared-key"]),
			"description":  "pfSense mobile key " + ident,
		})
	}

	report.Notes = append(report.Notes, fmt.Sprintf(
		"Mapped IPsec to OPNsense/Swanctl: %d connection(s), %d child SA(s); %d pre-shared key(s) under OPNsense/IPsec. Legacy Tunnel Settings XML is not written.",
		len(connections), len(children), len(psks)))
	if certNotes > 0 {
		report.Notes = append(report.Notes, "One or more IPsec tunnels use certificates. Assign the local/remote certs under VPN → IPsec → Connections after import (OPNsense stores them as IPsec key pairs).")
	}
	if dropped := droppedMobilePhase1(src); dropped > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"%d mobile/road-warrior IPsec phase 1(s) were not mapped (no remote-gateway). Recreate them under VPN → IPsec → Connections. %d mobile PSK(s) were copied.",
			dropped, len(mobile)))
	}

	ipsec = map[string]any{
		"general": map[string]any{"enabled": xmlutil.Present01(xmlutil.FlagSet(src["enable"]))},
	}
	if len(psks) > 0 {
		ipsec["preSharedKeys"] = map[string]any{"preSharedKey": psks}
	}

	if len(connections)+len(children)+len(locals)+len(remotes)+len(spds) == 0 {
		return ipsec, nil
	}
	swanctl = map[string]any{"@_version": "1.0.0"}
	if len(connections) > 0 {
		swanctl["Connections"] = map[string]any{"Connection": connections}
	}
	if len(children) > 0 {
		swanctl["children"] = map[string]any{"child": children}
	}
	if len(locals) > 0 {
		swanctl["locals"] = map[string]any{"local": locals}
	}
	if len(remotes) > 0 {
		swanctl["remotes"] = map[string]any{"remote": remotes}
	}
	if len(spds) > 0 {
		swanctl["SPDs"] = map[string]any{"SPD": spds}
	}
	return ipsec, swanctl
}

func usablePhase1(src map[string]any) []any {
	out := []any{}
	for _, raw := range xmlutil.AsArray(src["phase1"]) {
		p1 := xmlutil.Map(raw)
		if xmlutil.AsString(p1["remote-gateway"]) == "" {
			continue
		}
		out = append(out, p1)
	}
	return out
}

func droppedMobilePhase1(src map[string]any) int {
	n := 0
	for _, raw := range xmlutil.AsArray(src["phase1"]) {
		if xmlutil.AsString(xmlutil.Map(raw)["remote-gateway"]) == "" {
			n++
		}
	}
	return n
}

func reservedIkeIDs(phase1s []any) map[string]struct{} {
	used := map[string]struct{}{}
	for _, raw := range phase1s {
		if id := strings.TrimSpace(xmlutil.AsString(xmlutil.Map(raw)["ikeid"])); id != "" {
			used[id] = struct{}{}
		}
	}
	return used
}

func nextIkeID(raw string, reserved, claimed map[string]struct{}) string {
	id := strings.TrimSpace(raw)
	if id != "" {
		if _, taken := claimed[id]; !taken {
			claimed[id] = struct{}{}
			return id
		}
	}
	for n := 1; ; n++ {
		cand := strconv.Itoa(n)
		if _, taken := claimed[cand]; taken {
			continue
		}
		if _, later := reserved[cand]; later {
			continue
		}
		claimed[cand] = struct{}{}
		return cand
	}
}

func validPositiveInt(value any) string {
	n, err := strconv.Atoi(strings.TrimSpace(xmlutil.AsString(value)))
	if err != nil || n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func usableMobileKeys(src map[string]any) []any {
	out := []any{}
	for _, raw := range xmlutil.AsArray(src["mobilekey"]) {
		k := xmlutil.Map(raw)
		if xmlutil.AsString(k["ident"]) != "" && xmlutil.AsString(k["pre-shared-key"]) != "" {
			out = append(out, k)
		}
	}
	return out
}

// ikeVersion maps pfSense iketype onto the OPNsense Connection option list:
// 0 = IKEv1+IKEv2, 1 = IKEv1, 2 = IKEv2.
func ikeVersion(value any) string {
	switch v := xmlutil.LowerIdent(value); v {
	case "ikev2":
		return "2"
	case "ikev1":
		return "1"
	case "auto", "":
		return "0"
	default:
		if strings.Contains(v, "ikev2") {
			return "2"
		}
		if strings.Contains(v, "ikev1") {
			return "1"
		}
		return "0"
	}
}

// mobikeFlag reads the pfSense on/off string. Anything but an explicit "off"
// keeps MOBIKE on, which is also the OPNsense default.
func mobikeFlag(value any) string {
	if strings.EqualFold(strings.TrimSpace(xmlutil.AsString(value)), "off") {
		return "0"
	}
	return "1"
}

func dpdTimeout(delay, maxfail any) string {
	d, err := strconv.Atoi(strings.TrimSpace(xmlutil.AsString(delay)))
	if err != nil || d <= 0 {
		return ""
	}
	f, err := strconv.Atoi(strings.TrimSpace(xmlutil.AsString(maxfail)))
	if err != nil || f <= 0 {
		return ""
	}
	timeout := d * (f + 1)
	if timeout > 500000 {
		timeout = 500000
	}
	return strconv.Itoa(timeout)
}

// childMode collapses pfSense phase 2 modes onto the OPNsense option list
// (tunnel, transport, pass, drop).
func childMode(mode string) string {
	switch mode {
	case "transport":
		return "transport"
	case "", "tunnel", "tunnel6":
		return "tunnel"
	default: // vti / route-based
		return "tunnel"
	}
}

func childReqid(value any) string {
	n, err := strconv.Atoi(strings.TrimSpace(xmlutil.AsString(value)))
	if err != nil || n < 1 || n > 65535 {
		return ""
	}
	return strconv.Itoa(n)
}

// interfaceBindAddr resolves a pfSense interface reference (as used by IPsec
// phase 1 and OpenVPN instances) to a literal address. Dynamic interfaces are
// left blank so the daemon falls back to binding on any address.
func interfaceBindAddr(value any, ifaces map[string]any) string {
	key := xmlutil.LowerIdent(value)
	if key == "" || key == "any" {
		return ""
	}
	if net.ParseIP(key) != nil {
		return key
	}
	iface := xmlutil.Map(ifaces[key])
	if iface == nil {
		return ""
	}
	if ip := strings.TrimSpace(xmlutil.AsString(iface["ipaddr"])); net.ParseIP(ip) != nil {
		return ip
	}
	if ip := strings.TrimSpace(xmlutil.AsString(iface["ipaddrv6"])); net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

func pskIdent(localID, localAddr string) string {
	if localID != "" {
		return localID
	}
	if localAddr != "" {
		return localAddr
	}
	// OPNsense writes "id-0 = <ident>" and an empty value never matches.
	// %any is strongSwan's "any local identity" and is the safe default
	// when pfSense used "My IP address" on a dynamic WAN.
	return "%any"
}

func identValue(typ, data any, fallback string) string {
	t := strings.ToLower(xmlutil.AsString(typ))
	d := xmlutil.AsString(data)
	if t == "peeraddress" || t == "myaddress" || t == "none" {
		return fallback
	}
	if d != "" {
		return d
	}
	return fallback
}

func p1Proposals(p1 map[string]any) string {
	items := xmlutil.AsArray(xmlutil.Get(p1, "encryption", "item"))
	hash := p1["hash-algorithm"]
	dh := p1["dhgroup"]
	if len(items) == 0 {
		parts := oneProposal(p1["encryption-algorithm"], hash, dh)
		if len(parts) == 0 {
			return "aes256-sha256-modp2048"
		}
		return strings.Join(unique(parts), ",")
	}
	parts := []string{}
	for _, raw := range items {
		m := xmlutil.Map(raw)
		enc := orVal(m["encryption-algorithm"], m)
		parts = append(parts, oneProposal(enc, orVal(m["hash-algorithm"], hash), orVal(m["dhgroup"], dh))...)
	}
	if len(parts) == 0 {
		return "aes256-sha256-modp2048"
	}
	return strings.Join(unique(parts), ",")
}

func p2Proposals(p2 map[string]any) string {
	encs := []string{}
	for _, raw := range xmlutil.AsArray(p2["encryption-algorithm-option"]) {
		if m := xmlutil.Map(raw); m != nil {
			encs = append(encs, encTokens(xmlutil.AsString(m["name"]), xmlutil.AsString(m["keylen"]))...)
		} else if s := xmlutil.AsString(raw); s != "" {
			encs = append(encs, encTokens(s, "")...)
		}
	}
	hashes := []string{}
	for _, raw := range xmlutil.AsArray(p2["hash-algorithm-option"]) {
		if h := cleanHash(xmlutil.AsString(raw)); h != "" {
			hashes = append(hashes, h)
		}
	}
	dh := mapDH(xmlutil.AsString(p2["pfsgroup"]))
	if len(encs) == 0 {
		encs = []string{"aes256"}
	}
	if len(hashes) == 0 {
		hashes = []string{"sha256"}
	}
	parts := []string{}
	for _, enc := range encs {
		if isAEAD(enc) {
			p := enc
			if dh != "" {
				p += "-" + dh
			}
			parts = append(parts, p)
			continue
		}
		for _, h := range hashes {
			p := enc + "-" + h
			if dh != "" {
				p += "-" + dh
			}
			parts = append(parts, p)
		}
	}
	return strings.Join(unique(parts), ",")
}

func oneProposal(enc, hash, dh any) []string {
	var name, keylen string
	if m := xmlutil.Map(enc); m != nil {
		name = xmlutil.AsString(orVal(m["name"], m["encryption-algorithm"]))
		keylen = xmlutil.AsString(m["keylen"])
		if xmlutil.Map(m["encryption-algorithm"]) != nil {
			inner := xmlutil.Map(m["encryption-algorithm"])
			name = xmlutil.AsString(inner["name"])
			keylen = orDefault(xmlutil.AsString(inner["keylen"]), keylen)
		}
	} else {
		name = xmlutil.AsString(enc)
	}
	h := cleanHash(xmlutil.AsString(hash))
	d := mapDH(xmlutil.AsString(dh))
	out := []string{}
	for _, tok := range encTokens(name, keylen) {
		p := tok
		if h != "" && !isAEAD(tok) {
			p += "-" + h
		}
		if d != "" {
			p += "-" + d
		}
		out = append(out, p)
	}
	return out
}

var (
	digitRe     = regexp.MustCompile(`\d`)
	icvSuffixRe = regexp.MustCompile(`(gcm|ccm|gmac)(8|12|16)$`)
)

// autoKeyLengths mirrors OPNsense's ipsec_p2_ealgos(): a pfSense keylen of
// "auto" offers every key size the cipher supports.
var autoKeyLengths = map[string][]string{"aes": {"128", "192", "256"}}

// encTokens builds strongSwan cipher tokens. A non-numeric key length such as
// pfSense's "auto" must never be pasted onto the name ("aesauto" is not a
// cipher and OPNsense rejects the whole proposal).
func encTokens(name, keylen string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
	keylen = strings.ToLower(strings.TrimSpace(keylen))
	if name == "" {
		return nil
	}
	if isAEAD(name) {
		return []string{aeadToken(name, keylen)}
	}
	if keylen == "" || digitRe.MatchString(name) {
		return []string{name}
	}
	if _, err := strconv.Atoi(keylen); err == nil {
		return []string{name + keylen}
	}
	if sizes, ok := autoKeyLengths[name]; ok {
		out := make([]string, 0, len(sizes))
		for _, size := range sizes {
			out = append(out, name+size)
		}
		return out
	}
	return []string{name}
}

func isAEAD(token string) bool {
	t := strings.ToLower(token)
	return strings.Contains(t, "gcm") || strings.Contains(t, "ccm") || strings.Contains(t, "chacha20poly1305")
}

// aeadToken maps pfSense GCM/CCM + ICV bits onto strongSwan names
// (aes256gcm8 / aes256gcm12 / aes256gcm16). A missing ICV keeps the
// name as-is, which strongSwan treats as ICV-16.
func aeadToken(name, keylen string) string {
	if icvSuffixRe.MatchString(name) {
		return name
	}
	switch keylen {
	case "64":
		return name + "8"
	case "96":
		return name + "12"
	case "128":
		return name + "16"
	}
	return name
}

func cleanHash(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "hmac_")
	h = strings.TrimPrefix(h, "hmac-")
	return h
}

func mapDH(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" || strings.EqualFold(v, "off") {
		return ""
	}
	if mapped, ok := dhGroups[v]; ok {
		return mapped
	}
	return v
}

// trafficSelector mirrors OPNsense's ipsec_idinfo_to_cidr: an interface-typed
// selector means that interface's network, not its own address.
func trafficSelector(id any, ifaces map[string]any, mode string) string {
	m := xmlutil.Map(id)
	if m == nil {
		return ""
	}
	typ := xmlutil.LowerIdent(m["type"])
	addr := strings.TrimSpace(xmlutil.AsString(m["address"]))
	bits := strings.TrimSpace(xmlutil.AsString(m["netbits"]))
	switch typ {
	case "address":
		return addr
	case "network":
		if addr == "" {
			return ""
		}
		if bits == "" || strings.Contains(addr, "/") {
			return addr
		}
		return networkCIDR(addr, bits)
	case "none", "mobile":
		return ifThen(mode == "tunnel6", "::/0", "0.0.0.0/0")
	case "":
		return ""
	}
	iface := xmlutil.Map(ifaces[typ])
	if iface == nil {
		return ""
	}
	ipKey, maskKey := "ipaddr", "subnet"
	if mode == "tunnel6" {
		ipKey, maskKey = "ipaddrv6", "subnetv6"
	}
	ip := strings.TrimSpace(xmlutil.AsString(iface[ipKey]))
	mask := strings.TrimSpace(xmlutil.AsString(iface[maskKey]))
	if ip == "" || mask == "" || net.ParseIP(ip) == nil {
		return ""
	}
	return networkCIDR(ip, mask)
}

// networkCIDR clears the host bits so "192.168.1.1" + "24" becomes
// "192.168.1.0/24" rather than a selector with a host address in it.
func networkCIDR(addr, bits string) string {
	cidr := addr + "/" + bits
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	return ipnet.String()
}

var sha1Re = regexp.MustCompile(`(^|-)sha1($|-)`)

func weakProposal(proposal string) bool {
	s := strings.ToLower(proposal)
	weakDH := strings.Contains(s, "modp768") || strings.Contains(s, "modp1024") ||
		strings.Contains(s, "modp1536") || strings.Contains(s, "modp2048")
	weakHash := sha1Re.MatchString(s) || strings.Contains(s, "md5") ||
		strings.Contains(s, "-des-") || strings.HasPrefix(s, "des-") || strings.Contains(s, "3des")
	return weakHash || weakDH
}
