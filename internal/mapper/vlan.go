package mapper

import (
	"fmt"
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

var deviceNameKeys = map[string]struct{}{
	"if": {}, "vlanif": {}, "member": {}, "members": {}, "ports": {},
}

func mapVlans(pfsense map[string]any, opt *Options, report *Notes) (map[string]any, map[string]string) {
	vlans := xmlutil.AsArray(xmlutil.Get(pfsense, "vlans", "vlan"))
	if len(vlans) == 0 {
		return nil, nil
	}
	used := map[string]struct{}{}
	type pending struct {
		parent string
		tag    string
		old    string
		uuid   string
		pcp    string
		descr  string
		proto  string
	}
	items := make([]pending, 0, len(vlans))
	for _, raw := range vlans {
		v := xmlutil.Map(raw)
		if v == nil {
			continue
		}
		parent := xmlutil.AsString(v["if"])
		tag := xmlutil.AsString(v["tag"])
		old := xmlutil.AsString(v["vlanif"])
		if old == "" && parent != "" && tag != "" {
			old = parent + "." + tag
		}
		uuid := xmlutil.AsString(v["@_uuid"])
		if uuid == "" {
			uuid = nextUUID(opt)
		}
		if isOpnVLANDevice(old) {
			used[old] = struct{}{}
		}
		items = append(items, pending{
			parent: parent, tag: tag, old: old, uuid: uuid,
			pcp: orDefault(xmlutil.AsString(v["pcp"]), "0"), descr: xmlutil.AsString(v["descr"]),
			proto: xmlutil.AsString(v["proto"]),
		})
	}
	out := []any{}
	renames := map[string]string{}
	for _, it := range items {
		vlanif := it.old
		if !isOpnVLANDevice(vlanif) {
			vlanif = opnVLANDevice(it.tag, used)
			used[vlanif] = struct{}{}
			if it.old != "" && it.old != vlanif {
				renames[it.old] = vlanif
			}
		}
		item := map[string]any{
			"@_uuid": it.uuid,
			"if":     it.parent,
			"tag":    it.tag,
			"pcp":    it.pcp,
			"descr":  it.descr,
			"vlanif": vlanif,
		}
		if it.proto != "" {
			item["proto"] = it.proto
		}
		out = append(out, item)
	}
	if len(renames) > 0 && report != nil {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"Renamed %d VLAN device(s) to vlan0.<tag> (OPNsense 26.7 requires the vlan prefix; pfSense names like re0.10 are rejected).",
			len(renames)))
	}
	return map[string]any{"@_version": "1.0.0", "vlan": out}, renames
}

func isOpnVLANDevice(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	return strings.HasPrefix(n, "vlan") || strings.HasPrefix(n, "qinq")
}

func opnVLANDevice(tag string, used map[string]struct{}) string {
	if tag == "" {
		tag = "0"
	}
	base := "vlan0." + tag
	if _, taken := used[base]; !taken {
		return base
	}
	for i := 1; i < 1000; i++ {
		cand := fmt.Sprintf("%s.%d", base, i)
		if _, taken := used[cand]; !taken {
			return cand
		}
	}
	return base
}

func rewriteDeviceNames(node any, renames map[string]string) {
	if len(renames) == 0 {
		return
	}
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if _, ok := deviceNameKeys[k]; ok {
				s := xmlutil.AsString(v)
				if neu, hit := renames[s]; hit {
					n[k] = neu
					continue
				}
			}
			rewriteDeviceNames(v, renames)
		}
	case []any:
		for _, v := range n {
			rewriteDeviceNames(v, renames)
		}
	}
}

func normalizeOpnVLANs(cfg map[string]any, opt *Options) (bool, map[string]string) {
	block := xmlutil.Map(cfg["vlans"])
	if block == nil {
		return false, nil
	}
	fake := map[string]any{"vlans": block}
	mapped, renames := mapVlans(fake, opt, nil)
	if mapped == nil {
		return false, nil
	}
	changed := len(renames) > 0
	for _, raw := range xmlutil.AsArray(block["vlan"]) {
		if xmlutil.AsString(xmlutil.Map(raw)["@_uuid"]) == "" {
			changed = true
			break
		}
	}
	if xmlutil.AsString(block["@_version"]) == "" {
		changed = true
	}
	if !changed {
		return false, nil
	}
	cfg["vlans"] = mapped
	rewriteDeviceNames(cfg, renames)
	return true, renames
}
