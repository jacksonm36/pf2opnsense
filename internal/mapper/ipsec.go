package mapper

import (
	"fmt"
	"regexp"
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

	ikeToUUID := map[string]string{}
	connections := []any{}
	locals := []any{}
	remotes := []any{}
	psks := []any{}
	children := []any{}
	spds := []any{}
	certNotes := 0

	for _, raw := range phase1s {
		p1 := xmlutil.Map(raw)
		ikeid := orDefault(xmlutil.AsString(p1["ikeid"]), fmt.Sprintf("%d", len(connections)+1))
		connUUID := nextUUID(opt)
		ikeToUUID[ikeid] = connUUID
		descr := orDefault(xmlutil.AsString(p1["descr"]), "IKE "+ikeid)
		remoteGW := xmlutil.AsString(p1["remote-gateway"])
		auth := strings.ToLower(xmlutil.AsString(p1["authentication_method"]))

		conn := map[string]any{
			"@_uuid":       connUUID,
			"enabled":      ifThen(xmlutil.FlagSet(p1["disabled"]), "0", "1"),
			"proposals":    p1Proposals(p1),
			"unique":       "no",
			"aggressive":   ifThen(strings.ToLower(xmlutil.AsString(p1["mode"])) == "aggressive", "1", "0"),
			"version":      ikeVersion(p1["iketype"]),
			"mobike":       xmlutil.Present01(orVal(p1["mobike"], "1")),
			"remote_addrs": remoteGW,
			"encap":        ifThen(strings.ToLower(xmlutil.AsString(p1["nat_traversal"])) == "off", "0", "1"),
			"rekey_time":   xmlutil.AsString(p1["lifetime"]),
			"dpd_delay":    xmlutil.AsString(p1["dpd_delay"]),
			"send_certreq": "1",
			"description":  descr,
		}
		connections = append(connections, conn)

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
				psks = append(psks, map[string]any{
					"@_uuid":       nextUUID(opt),
					"ident":        localID,
					"remote_ident": orDefault(remoteID, remoteGW),
					"keyType":      "PSK",
					"Key":          psk,
					"description":  descr,
				})
			}
		}
	}

	ifaces := xmlutil.Map(pfsense["interfaces"])
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
		child := map[string]any{
			"@_uuid":        childUUID,
			"enabled":       ifThen(xmlutil.FlagSet(p2["disabled"]), "0", "1"),
			"connection":    parent,
			"reqid":         xmlutil.AsString(p2["reqid"]),
			"esp_proposals": esp,
			"sha256_96":     "0",
			"start_action":  "start",
			"close_action":  "none",
			"dpd_action":    "clear",
			"mode":          orDefault(xmlutil.AsString(p2["mode"]), "tunnel"),
			"policies":      "1",
			"local_ts":      trafficSelector(p2["localid"], ifaces),
			"remote_ts":     trafficSelector(p2["remoteid"], ifaces),
			"rekey_time":    xmlutil.AsString(p2["lifetime"]),
			"description":   descr,
		}
		if weakESP(esp) {
			report.Notes = append(report.Notes, fmt.Sprintf(
				`IPsec child "%s" imported with ESP %s. SHA-1 and/or DH ≤ modp2048 are weak on OPNsense 26.7; coordinate an upgrade (e.g. aes256-sha256-modp3072) with the remote peer.`,
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
		psks = append(psks, map[string]any{
			"@_uuid":       nextUUID(opt),
			"ident":        xmlutil.AsString(k["ident"]),
			"remote_ident": "",
			"keyType":      "PSK",
			"Key":          xmlutil.AsString(k["pre-shared-key"]),
			"description":  "pfSense mobile key " + xmlutil.AsString(k["ident"]),
		})
	}

	report.Notes = append(report.Notes, fmt.Sprintf(
		"Mapped IPsec to OPNsense/Swanctl: %d connection(s), %d child SA(s); %d pre-shared key(s) under OPNsense/IPsec. Legacy Tunnel Settings XML is not written.",
		len(connections), len(children), len(psks)))
	if certNotes > 0 {
		report.Notes = append(report.Notes, "One or more IPsec tunnels use certificates. Assign the local/remote certs under VPN → IPsec → Connections after import (OPNsense stores them as IPsec key pairs).")
	}
	if xmlutil.Map(src["client"]) != nil && len(connections) == 0 && len(mobile) > 0 {
		report.Notes = append(report.Notes, "Mobile IPsec (road warrior) PSKs were copied. Recreate the mobile connection itself under VPN → IPsec → Connections.")
	}

	ipsec = map[string]any{
		"general": map[string]any{"enabled": "1"},
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

func ikeVersion(value any) string {
	v := strings.ToLower(xmlutil.AsString(value))
	if strings.Contains(v, "ikev2") || v == "ikev2" {
		return "2"
	}
	if strings.Contains(v, "ikev1") {
		return "1"
	}
	return "2"
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
		p := oneProposal(p1["encryption-algorithm"], hash, dh)
		if p == "" {
			return "aes256-sha256-modp2048"
		}
		return p
	}
	parts := []string{}
	for _, raw := range items {
		m := xmlutil.Map(raw)
		enc := orVal(m["encryption-algorithm"], m)
		p := oneProposal(enc, orVal(m["hash-algorithm"], hash), orVal(m["dhgroup"], dh))
		if p != "" {
			parts = append(parts, p)
		}
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
			if tok := encToken(xmlutil.AsString(m["name"]), xmlutil.AsString(m["keylen"])); tok != "" {
				encs = append(encs, tok)
			}
		} else if s := xmlutil.AsString(raw); s != "" {
			encs = append(encs, encToken(s, ""))
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

func oneProposal(enc, hash, dh any) string {
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
	tok := encToken(name, keylen)
	if tok == "" {
		return ""
	}
	h := cleanHash(xmlutil.AsString(hash))
	d := mapDH(xmlutil.AsString(dh))
	p := tok
	if h != "" && !strings.Contains(tok, "gcm") {
		p += "-" + h
	} else if h != "" && strings.Contains(tok, "gcm") {
		p += "-" + h
	}
	if d != "" {
		p += "-" + d
	}
	return p
}

func encToken(name, keylen string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	keylen = strings.TrimSpace(keylen)
	if name == "" {
		return ""
	}
	if keylen != "" && !regexp.MustCompile(`\d`).MatchString(name) {
		return name + keylen
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

func trafficSelector(id any, ifaces map[string]any) string {
	m := xmlutil.Map(id)
	if m == nil {
		return ""
	}
	typ := xmlutil.LowerIdent(m["type"])
	addr := xmlutil.AsString(m["address"])
	bits := xmlutil.AsString(m["netbits"])
	if typ == "network" || typ == "address" {
		if addr == "" {
			return ""
		}
		if bits != "" && !strings.Contains(addr, "/") {
			return addr + "/" + bits
		}
		return addr
	}
	if typ == "none" || typ == "" {
		return ""
	}
	iface := xmlutil.Map(ifaces[typ])
	if iface == nil {
		return ""
	}
	ip := xmlutil.AsString(iface["ipaddr"])
	mask := xmlutil.AsString(iface["subnet"])
	if ip == "" || mask == "" || ip == "dhcp" {
		return ""
	}
	return ip + "/" + mask
}

func weakESP(esp string) bool {
	s := strings.ToLower(esp)
	sha1 := regexp.MustCompile(`(^|-)sha1($|-)`).MatchString(s)
	weakDH := strings.Contains(s, "modp768") || strings.Contains(s, "modp1024") ||
		strings.Contains(s, "modp1536") || strings.Contains(s, "modp2048")
	return sha1 || weakDH
}
