package validate

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/mapper"
	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

type Check struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Report struct {
	Checks      []Check `json:"checks"`
	Passed      int     `json:"passed"`
	Warnings    int     `json:"warnings"`
	Errors      int     `json:"errors"`
	Skipped     int     `json:"skipped"`
	CanDownload bool    `json:"canDownload"`
}

type Context struct {
	FileName    string
	RawText     string
	ParsedInput map[string]any
	MappedRoot  map[string]any
	OutputXML   string
	Report      *mapper.Notes
	ConvertErr  string
}

func pass(id, group, title, detail string) Check {
	return Check{ID: id, Group: group, Title: title, Status: "pass", Detail: detail}
}
func warn(id, group, title, detail string) Check {
	return Check{ID: id, Group: group, Title: title, Status: "warn", Detail: detail}
}
func fail(id, group, title, detail string) Check {
	return Check{ID: id, Group: group, Title: title, Status: "fail", Detail: detail}
}
func skip(id, group, title, detail string) Check {
	return Check{ID: id, Group: group, Title: title, Status: "skip", Detail: detail}
}

var encryptedRe = regexp.MustCompile(`(?i)BEGIN.*?config\.xml|-----BEGIN (PGP |AES |ENCRYPTED)`)

func Run(ctx Context) Report {
	checks := []Check{
		checkInputXML(ctx),
		checkRoot(ctx),
		checkRevision(ctx),
		checkSystem(ctx),
		checkInterfaces(ctx),
		checkFilter(ctx),
		checkOpenVPNIn(ctx),
		checkConvert(ctx),
		checkOutputXML(ctx),
		checkOutputSystem(ctx),
		checkFirewall(ctx),
		checkAliases(ctx),
		checkOpenVPNOut(ctx),
		checkGateways(ctx),
		checkDHCP(ctx),
		checkVLANs(ctx),
		checkTrust(ctx),
		checkIPsec(ctx),
		checkPPPs(ctx),
		checkSyslog(ctx),
		checkCron(ctx),
		checkDynDNS(ctx),
		checkOvpnWizard(ctx),
	}
	xmlFailed, rootFailed, convertFailed := false, false, false
	for _, c := range checks {
		if c.ID == "input-xml" && c.Status == "fail" {
			xmlFailed = true
		}
		if c.ID == "input-root" && c.Status == "fail" {
			rootFailed = true
		}
		if c.ID == "convert-map" && c.Status == "fail" {
			convertFailed = true
		}
	}
	out := make([]Check, 0, len(checks))
	for _, c := range checks {
		if xmlFailed && c.ID != "input-xml" {
			out = append(out, skip(c.ID, c.Group, c.Title, "Skipped because the file is not valid XML."))
			continue
		}
		if rootFailed && c.ID != "input-xml" && c.ID != "input-root" {
			out = append(out, skip(c.ID, c.Group, c.Title, "Skipped because this is not a pfSense config."))
			continue
		}
		if convertFailed && c.Group == "output" {
			out = append(out, skip(c.ID, c.Group, c.Title, "Skipped because conversion failed."))
			continue
		}
		out = append(out, c)
	}
	return summarize(out)
}

func summarize(checks []Check) Report {
	r := Report{Checks: checks}
	for _, c := range checks {
		switch c.Status {
		case "pass":
			r.Passed++
		case "warn":
			r.Warnings++
		case "fail":
			r.Errors++
		case "skip":
			r.Skipped++
		}
	}
	r.CanDownload = r.Errors == 0 && len(checks) > 0
	return r
}

func pfsense(ctx Context) map[string]any {
	return xmlutil.Map(ctx.ParsedInput["pfsense"])
}
func opnsense(ctx Context) map[string]any {
	return xmlutil.Map(xmlutil.Get(ctx.MappedRoot, "opnsense"))
}
func source(ctx Context) map[string]any {
	if pf := pfsense(ctx); pf != nil {
		return pf
	}
	if in := xmlutil.Map(ctx.ParsedInput["opnsense"]); in != nil {
		return in
	}
	return nil
}
func isOpnInput(ctx Context) bool {
	return pfsense(ctx) == nil && xmlutil.Map(ctx.ParsedInput["opnsense"]) != nil
}

func checkInputXML(ctx Context) Check {
	title := "Well-formed XML"
	if strings.TrimSpace(ctx.RawText) == "" {
		return fail("input-xml", "input", title, "The uploaded file is empty.")
	}
	if encryptedRe.MatchString(ctx.RawText) && !strings.Contains(ctx.RawText, "<pfsense") && !strings.Contains(ctx.RawText, "<opnsense") {
		return fail("input-xml", "input", title, "Encrypted pfSense backup detected. Restore requires a plain config.xml.")
	}
	if err := xmlutil.WellFormed(strings.TrimSpace(ctx.RawText)); err != nil {
		return fail("input-xml", "input", title, err.Error())
	}
	name := ctx.FileName
	if name == "" {
		name = "config.xml"
	}
	return pass("input-xml", "input", title, name+" parsed as XML.")
}

func checkRoot(ctx Context) Check {
	title := "Configuration document"
	if pfsense(ctx) != nil {
		return pass("input-root", "input", title, "Found a pfSense configuration document.")
	}
	if xmlutil.Map(ctx.ParsedInput["opnsense"]) != nil {
		return pass("input-root", "input", title, "Found an OPNsense configuration document. DHCP can be remapped to dnsmasq or Kea.")
	}
	return fail("input-root", "input", title, "Missing <pfsense> or <opnsense> root. This is not a firewall configuration backup.")
}

func checkRevision(ctx Context) Check {
	if isOpnInput(ctx) {
		return pass("input-revision", "input", "OPNsense source", "OPNsense backup accepted. Other settings are kept; DHCP backend follows the selected option.")
	}
	title := "pfSense " + mapper.PfRelease + " revision"
	version := xmlutil.AsString(xmlutil.Get(pfsense(ctx), "version"))
	if version == "" {
		return warn("input-revision", "input", title, "No <version> tag. Expected config revision "+mapper.PfRevision+" (pfSense "+mapper.PfRelease+").")
	}
	if version == mapper.PfRevision {
		return pass("input-revision", "input", title, "Config revision "+version+" matches pfSense "+mapper.PfRelease+".")
	}
	return warn("input-revision", "input", title, "Config revision is "+version+", not "+mapper.PfRevision+" (pfSense "+mapper.PfRelease+"). Mapping still runs.")
}

func checkSystem(ctx Context) Check {
	title := "System identity"
	src := source(ctx)
	hostname := xmlutil.AsString(xmlutil.Get(src, "system", "hostname"))
	if hostname == "" {
		return fail("input-system", "input", title, "No system hostname. Restore needs a hostname.")
	}
	users := xmlutil.AsArray(xmlutil.Get(src, "system", "user"))
	if len(users) > 0 {
		return pass("input-system", "input", title, fmt.Sprintf("Hostname %s, %d local user(s).", hostname, len(users)))
	}
	return pass("input-system", "input", title, "Hostname "+hostname+".")
}

func checkInterfaces(ctx Context) Check {
	title := "Interface assignments"
	ifaces := xmlutil.Map(xmlutil.Get(source(ctx), "interfaces"))
	names := []string{}
	withDev := 0
	for name, val := range ifaces {
		if xmlutil.Map(val) == nil && len(xmlutil.AsArray(val)) == 0 {
			continue
		}
		names = append(names, name)
		iface := xmlutil.Map(val)
		if arr := xmlutil.AsArray(val); len(arr) > 0 {
			iface = xmlutil.Map(arr[0])
		}
		if iface == nil {
			continue
		}
		if xmlutil.AsString(iface["if"]) != "" || xmlutil.AsString(iface["ipaddr"]) != "" {
			withDev++
		}
	}
	if len(names) == 0 {
		return fail("input-interfaces", "input", title, "No interface assignments found.")
	}
	if withDev == 0 {
		return fail("input-interfaces", "input", title, "Interfaces exist but none have a device or address.")
	}
	return pass("input-interfaces", "input", title, "Found "+strings.Join(names, ", ")+".")
}

func checkFilter(ctx Context) Check {
	title := "Firewall rules present"
	if isOpnInput(ctx) {
		return skip("input-filter", "input", title, "OPNsense firewall rules are kept as-is.")
	}
	count := len(xmlutil.AsArray(xmlutil.Get(pfsense(ctx), "filter", "rule"))) + len(xmlutil.AsArray(xmlutil.Get(pfsense(ctx), "firewall", "rule")))
	if count == 0 {
		return warn("input-filter", "input", title, "No filter rules found. OPNsense will only get default-style mapped rules if any exist.")
	}
	return pass("input-filter", "input", title, fmt.Sprintf("%d pfSense filter rule(s) will be mapped to OPNsense Firewall MVC.", count))
}

func checkOpenVPNIn(ctx Context) Check {
	title := "OpenVPN source"
	if isOpnInput(ctx) {
		return skip("input-openvpn", "input", title, "OPNsense OpenVPN is kept as-is.")
	}
	ovpn := xmlutil.Map(xmlutil.Get(pfsense(ctx), "openvpn"))
	servers := len(xmlutil.AsArray(ovpn["openvpn-server"]))
	clients := len(xmlutil.AsArray(ovpn["openvpn-client"]))
	users := len(xmlutil.AsArray(ovpn["openvpn-csc"]))
	if servers+clients+users == 0 {
		return skip("input-openvpn", "input", title, "No OpenVPN section in this backup.")
	}
	return pass("input-openvpn", "input", title, fmt.Sprintf("%d server(s), %d client(s), %d client-specific user override(s) will be mapped to Instances.", servers, clients, users))
}

func checkConvert(ctx Context) Check {
	title := "pfSense → OPNsense " + mapper.OpnSeries + " map"
	if isOpnInput(ctx) {
		title = "OPNsense DHCP remap (" + mapper.OpnSeries + ")"
	}
	if ctx.ConvertErr != "" {
		return fail("convert-map", "convert", title, ctx.ConvertErr)
	}
	if xmlutil.Get(ctx.MappedRoot, "opnsense") == nil {
		return fail("convert-map", "convert", title, "Mapper did not produce an OPNsense document.")
	}
	if ctx.Report != nil {
		s := ctx.Report.Stats
		return pass("convert-map", "convert", title, fmt.Sprintf("%d rules, %d aliases, %d OpenVPN servers, %d users.", s.FilterRules, s.Aliases, s.OpenvpnServers, s.Users))
	}
	return pass("convert-map", "convert", title, "Mapper produced an OPNsense document.")
}

func checkOutputXML(ctx Context) Check {
	title := "Generated XML is well-formed"
	if ctx.OutputXML == "" {
		return fail("output-xml", "output", title, "No XML was generated.")
	}
	if err := xmlutil.WellFormed(ctx.OutputXML); err != nil {
		return fail("output-xml", "output", title, err.Error())
	}
	if !strings.Contains(ctx.OutputXML, "<opnsense>") {
		return fail("output-xml", "output", title, "Generated document is missing an <opnsense> root.")
	}
	if strings.Contains(ctx.OutputXML, "<pfsense>") {
		return fail("output-xml", "output", title, "Generated document still contains <pfsense>.")
	}
	return pass("output-xml", "output", title, fmt.Sprintf("Well-formed OPNsense XML (%d bytes).", len(ctx.OutputXML)))
}

func checkOutputSystem(ctx Context) Check {
	title := "OPNsense system / root account"
	system := xmlutil.Map(xmlutil.Get(opnsense(ctx), "system"))
	hostname := xmlutil.AsString(system["hostname"])
	if hostname == "" {
		return fail("output-system", "output", title, "Mapped config has no hostname.")
	}
	var root map[string]any
	for _, raw := range xmlutil.AsArray(system["user"]) {
		u := xmlutil.Map(raw)
		if xmlutil.AsString(u["uid"]) == "0" {
			root = u
			break
		}
	}
	if root == nil {
		if isOpnInput(ctx) {
			return pass("output-system", "output", title, "Hostname "+hostname+". Local users were left as in the OPNsense backup.")
		}
		return fail("output-system", "output", title, "No uid 0 user. OPNsense restore requires root.")
	}
	if xmlutil.AsString(root["name"]) != "root" {
		return fail("output-system", "output", title, fmt.Sprintf(`uid 0 is named "%s"; OPNsense requires the name root.`, xmlutil.AsString(root["name"])))
	}
	return pass("output-system", "output", title, "Hostname "+hostname+", uid 0 is root.")
}

func checkFirewall(ctx Context) Check {
	title := "Firewall rules are MVC (26.7)"
	if isOpnInput(ctx) {
		return skip("output-firewall", "output", title, "OPNsense firewall layout was not rewritten.")
	}
	opn := opnsense(ctx)
	rules := xmlutil.AsArray(xmlutil.Get(opn, "OPNsense", "Firewall", "Filter", "rules", "rule"))
	legacy := xmlutil.Map(opn["filter"])
	if legacy != nil && len(xmlutil.AsArray(legacy["rule"])) > 0 {
		return fail("output-firewall", "output", title, "Legacy <filter><rule> is still populated. OPNsense 26.7 expects OPNsense/Firewall/Filter.")
	}
	if xmlutil.Get(opn, "OPNsense", "Firewall", "Filter") == nil {
		return fail("output-firewall", "output", title, "Missing OPNsense/Firewall/Filter MVC block.")
	}
	inCount := len(xmlutil.AsArray(xmlutil.Get(pfsense(ctx), "filter", "rule"))) + len(xmlutil.AsArray(xmlutil.Get(pfsense(ctx), "firewall", "rule")))
	if inCount > 0 && len(rules) == 0 {
		return warn("output-firewall", "output", title, "Input had filter rules but none were mapped (they may have been match/separator rules).")
	}
	return pass("output-firewall", "output", title, fmt.Sprintf("%d rule(s) in OPNsense/Firewall/Filter. Legacy filter left empty.", len(rules)))
}

func checkAliases(ctx Context) Check {
	title := "Aliases are MVC"
	in := xmlutil.AsArray(xmlutil.Get(pfsense(ctx), "aliases", "alias"))
	if len(in) == 0 {
		return skip("output-aliases", "output", title, "Source config has no aliases.")
	}
	out := xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "OPNsense", "Firewall", "Alias", "aliases", "alias"))
	if len(out) == 0 {
		return fail("output-aliases", "output", title, "Source aliases were not written to OPNsense/Firewall/Alias.")
	}
	for _, raw := range out {
		content := xmlutil.AsString(xmlutil.Map(raw)["content"])
		glued := regexp.MustCompile(`[0-9]\d+\.\d+\.\d+\.\d+[0-9]`).MatchString(strings.ReplaceAll(content, "\n", ""))
		if glued && !strings.Contains(content, "\n") && strings.Count(content, ".") > 3 {
			return fail("output-aliases", "output", title, "Alias addresses look concatenated without separators.")
		}
	}
	return pass("output-aliases", "output", title, fmt.Sprintf("%d alias(es) under OPNsense/Firewall/Alias with newline-separated content.", len(out)))
}

func checkOpenVPNOut(ctx Context) Check {
	title := "OpenVPN Instances (not legacy)"
	in := xmlutil.Map(xmlutil.Get(pfsense(ctx), "openvpn"))
	had := len(xmlutil.AsArray(in["openvpn-server"]))+len(xmlutil.AsArray(in["openvpn-client"]))+len(xmlutil.AsArray(in["openvpn-csc"])) > 0
	out := opnsense(ctx)
	legacy := xmlutil.Map(out["openvpn"])
	if legacy != nil && (legacy["openvpn-server"] != nil || legacy["openvpn-csc"] != nil) {
		return fail("output-openvpn", "output", title, "Legacy <openvpn-server>/<openvpn-csc> is still in the output. OPNsense 26.7 uses VPN → OpenVPN → Instances.")
	}
	if !had {
		return skip("output-openvpn", "output", title, "No OpenVPN in the source config.")
	}
	instances := xmlutil.AsArray(xmlutil.Get(out, "OPNsense", "OpenVPN", "Instances", "Instance"))
	overwrites := xmlutil.AsArray(xmlutil.Get(out, "OPNsense", "OpenVPN", "Overwrites", "Overwrite"))
	if len(instances) == 0 {
		return fail("output-openvpn", "output", title, "Source OpenVPN was not mapped to OPNsense/OpenVPN/Instances.")
	}
	return pass("output-openvpn", "output", title, fmt.Sprintf("%d Instance(s), %d user overwrite(s), under VPN → OpenVPN → Instances.", len(instances), len(overwrites)))
}

func checkGateways(ctx Context) Check {
	title := "Gateways MVC"
	in := xmlutil.AsArray(xmlutil.Get(pfsense(ctx), "gateways", "gateway_item"))
	if len(in) == 0 {
		return skip("output-gateways", "output", title, "No pfSense gateways to map.")
	}
	items := xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "OPNsense", "Gateways", "gateway_item"))
	if len(items) == 0 {
		return fail("output-gateways", "output", title, "Gateways were not written to OPNsense/Gateways.")
	}
	for _, raw := range items {
		w, _ := strconv.Atoi(xmlutil.AsString(xmlutil.Map(raw)["weight"]))
		if w > 10 {
			return fail("output-gateways", "output", title, "A gateway weight is still above 10 (OPNsense max).")
		}
	}
	return pass("output-gateways", "output", title, fmt.Sprintf("%d gateway(s) in OPNsense/Gateways with valid weights.", len(items)))
}

func checkDHCP(ctx Context) Check {
	title := "DHCP → dnsmasq or Kea"
	src := source(ctx)
	had := sourceHasDHCP(src)
	if !had {
		return skip("output-dhcp", "output", title, "No DHCP pools in the source config.")
	}
	ranges := xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "dnsmasq", "dhcp_ranges"))
	keaOn := keaDHCPEnabled(opnsense(ctx))
	keaSubs := xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "OPNsense", "Kea", "dhcp4", "subnets", "subnet4"))
	if len(ranges) > 0 && keaOn && len(keaSubs) > 0 {
		return fail("output-dhcp", "output", title, "Both dnsmasq DHCP and Kea are enabled. Pick one backend.")
	}
	if keaOn && len(keaSubs) > 0 {
		res := xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "OPNsense", "Kea", "dhcp4", "reservations", "reservation"))
		return pass("output-dhcp", "output", title, fmt.Sprintf(
			"%d Kea subnet(s) and %d reservation(s) for OPNsense %s.", len(keaSubs), len(res), mapper.OpnSeries))
	}
	if len(ranges) == 0 {
		return fail("output-dhcp", "output", title, "DHCP pools were not mapped to dnsmasq dhcp_ranges or Kea subnets.")
	}
	missingUUID := 0
	for _, raw := range ranges {
		if xmlutil.AsString(xmlutil.Map(raw)["@_uuid"]) == "" {
			missingUUID++
		}
	}
	for _, raw := range xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "dnsmasq", "hosts")) {
		if xmlutil.AsString(xmlutil.Map(raw)["@_uuid"]) == "" {
			missingUUID++
		}
	}
	if missingUUID > 0 {
		return fail("output-dhcp", "output", title, fmt.Sprintf("%d dnsmasq host/range item(s) have no uuid. OPNsense Hosts UI cannot delete them.", missingUUID))
	}
	return pass("output-dhcp", "output", title, fmt.Sprintf("%d dnsmasq DHCP range(s) for OPNsense %s.", len(ranges), mapper.OpnSeries))
}

func sourceHasDHCP(src map[string]any) bool {
	if src == nil {
		return false
	}
	for _, cfg := range xmlutil.Map(src["dhcpd"]) {
		m := xmlutil.Map(cfg)
		if xmlutil.AsString(xmlutil.Get(m, "range", "from")) != "" && xmlutil.AsString(xmlutil.Get(m, "range", "to")) != "" {
			return true
		}
	}
	if len(xmlutil.AsArray(xmlutil.Get(src, "dnsmasq", "dhcp_ranges"))) > 0 {
		return true
	}
	if keaDHCPEnabled(src) && len(xmlutil.AsArray(xmlutil.Get(src, "OPNsense", "Kea", "dhcp4", "subnets", "subnet4"))) > 0 {
		return true
	}
	return false
}

func keaDHCPEnabled(root map[string]any) bool {
	en := xmlutil.Get(root, "OPNsense", "Kea", "dhcp4", "general", "enabled")
	if en == nil {
		return len(xmlutil.AsArray(xmlutil.Get(root, "OPNsense", "Kea", "dhcp4", "subnets", "subnet4"))) > 0
	}
	return xmlutil.FlagSet(en)
}

func checkVLANs(ctx Context) Check {
	title := "VLAN devices have UUIDs"
	in := xmlutil.AsArray(xmlutil.Get(source(ctx), "vlans", "vlan"))
	if len(in) == 0 {
		return skip("output-vlans", "output", title, "No VLANs in the source config.")
	}
	out := xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "vlans", "vlan"))
	if len(out) == 0 {
		return fail("output-vlans", "output", title, "Source VLANs were not written. OPNsense Interfaces → Devices → VLAN will be empty.")
	}
	missingUUID, missingDev := 0, 0
	for _, raw := range out {
		v := xmlutil.Map(raw)
		if xmlutil.AsString(v["@_uuid"]) == "" {
			missingUUID++
		}
		if xmlutil.AsString(v["vlanif"]) == "" || xmlutil.AsString(v["if"]) == "" || xmlutil.AsString(v["tag"]) == "" {
			missingDev++
		}
	}
	if missingUUID > 0 {
		return fail("output-vlans", "output", title, fmt.Sprintf("%d VLAN(s) have no uuid. OPNsense Edit VLAN will show empty Device/Parent/tag fields.", missingUUID))
	}
	if missingDev > 0 {
		return fail("output-vlans", "output", title, fmt.Sprintf("%d VLAN(s) are missing parent, tag, or device name.", missingDev))
	}
	badName := 0
	for _, raw := range out {
		vlanif := strings.ToLower(xmlutil.AsString(xmlutil.Map(raw)["vlanif"]))
		if !strings.HasPrefix(vlanif, "vlan") && !strings.HasPrefix(vlanif, "qinq") {
			badName++
		}
	}
	if badName > 0 {
		return fail("output-vlans", "output", title, fmt.Sprintf("%d VLAN device name(s) do not start with vlan/qinq. OPNsense 26.7 rejects names like re0.10.", badName))
	}
	return pass("output-vlans", "output", title, fmt.Sprintf("%d VLAN device(s) named vlan0.<tag> with uuid.", len(out)))
}

func pki(value any) []map[string]any {
	out := []map[string]any{}
	for _, raw := range xmlutil.AsArray(value) {
		if m := xmlutil.Map(raw); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func looksLikePEM(blob string, re *regexp.Regexp) bool {
	compact := regexp.MustCompile(`\s+`).ReplaceAllString(blob, "")
	if compact == "" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return false
	}
	return re.Match(decoded)
}

func checkTrust(ctx Context) Check {
	title := "Certificates and CAs"
	inCA, inCert := pki(xmlutil.Get(pfsense(ctx), "ca")), pki(xmlutil.Get(pfsense(ctx), "cert"))
	if len(inCA)+len(inCert) == 0 {
		return skip("output-trust", "output", title, "Source config has no CA or certificate entries.")
	}
	outCA, outCert := pki(xmlutil.Get(opnsense(ctx), "ca")), pki(xmlutil.Get(opnsense(ctx), "cert"))
	if len(inCA) > 0 && len(outCA) != len(inCA) {
		return fail("output-trust", "output", title, fmt.Sprintf("Source had %d CA(s) but output has %d.", len(inCA), len(outCA)))
	}
	if len(inCert) > 0 && len(outCert) != len(inCert) {
		return fail("output-trust", "output", title, fmt.Sprintf("Source had %d certificate(s) but output has %d.", len(inCert), len(outCert)))
	}
	caIDs := map[string]struct{}{}
	for _, ca := range outCA {
		if id := xmlutil.AsString(ca["refid"]); id != "" {
			caIDs[id] = struct{}{}
		}
	}
	missing := 0
	for _, item := range append(append([]map[string]any{}, outCA...), outCert...) {
		if !looksLikePEM(xmlutil.AsString(item["crt"]), regexp.MustCompile(`BEGIN CERTIFICATE`)) {
			missing++
		}
	}
	if missing > 0 {
		return fail("output-trust", "output", title, fmt.Sprintf("%d CA/certificate blob(s) are missing a base64 PEM certificate.", missing))
	}
	dangling := 0
	weak := 0
	users := 0
	for _, cert := range outCert {
		if caref := xmlutil.AsString(cert["caref"]); caref != "" {
			if _, ok := caIDs[caref]; !ok {
				dangling++
			}
		}
		if xmlutil.AsString(cert["prv"]) != "" && !looksLikePEM(xmlutil.AsString(cert["prv"]), regexp.MustCompile(`BEGIN .*PRIVATE KEY`)) {
			weak++
		}
		if xmlutil.AsString(cert["type"]) == "user" {
			users++
		}
	}
	if dangling > 0 {
		return fail("output-trust", "output", title, fmt.Sprintf("%d certificate(s) reference a CA that was not copied.", dangling))
	}
	detail := fmt.Sprintf("%d CA(s), %d certificate(s)", len(outCA), len(outCert))
	if users > 0 {
		detail += fmt.Sprintf(", %d user cert(s)", users)
	}
	detail += " copied with matching refids."
	if weak > 0 {
		return warn("output-trust", "output", title, fmt.Sprintf("%s %d private key(s) are not valid PEM — System → Trust after import.", detail, weak))
	}
	return pass("output-trust", "output", title, detail)
}

func checkIPsec(ctx Context) Check {
	title := "IPsec Connections"
	out := opnsense(ctx)
	if xmlutil.Get(out, "OPNsense", "IPsec", "Swanctl") != nil {
		return fail("output-ipsec", "output", title, "Swanctl is nested under OPNsense/IPsec/Swanctl. OPNsense 26.7 mounts it at OPNsense/Swanctl; run_migrations.php will drop the nested copy.")
	}
	legacy := xmlutil.Map(xmlutil.Get(out, "ipsec"))
	if legacy != nil {
		for _, raw := range xmlutil.AsArray(legacy["phase1"]) {
			if xmlutil.AsString(xmlutil.Map(raw)["remote-gateway"]) != "" {
				return fail("output-ipsec", "output", title, "Legacy <ipsec><phase1> is still in the output. OPNsense 26.7 uses VPN → IPsec → Connections.")
			}
		}
	}

	p1, p2, mobile := countPfSenseIPsec(pfsense(ctx))
	src := source(ctx)
	srcConns := len(xmlutil.AsArray(xmlutil.Get(src, "OPNsense", "Swanctl", "Connections", "Connection"))) +
		len(xmlutil.AsArray(xmlutil.Get(src, "OPNsense", "IPsec", "Swanctl", "Connections", "Connection")))
	srcChildren := len(xmlutil.AsArray(xmlutil.Get(src, "OPNsense", "Swanctl", "children", "child"))) +
		len(xmlutil.AsArray(xmlutil.Get(src, "OPNsense", "IPsec", "Swanctl", "children", "child")))
	srcPSKs := len(xmlutil.AsArray(xmlutil.Get(src, "OPNsense", "IPsec", "preSharedKeys", "preSharedKey")))

	conns := xmlutil.AsArray(xmlutil.Get(out, "OPNsense", "Swanctl", "Connections", "Connection"))
	children := xmlutil.AsArray(xmlutil.Get(out, "OPNsense", "Swanctl", "children", "child"))
	psks := xmlutil.AsArray(xmlutil.Get(out, "OPNsense", "IPsec", "preSharedKeys", "preSharedKey"))

	if p1+mobile+srcConns+srcPSKs == 0 {
		return skip("output-ipsec", "output", title, "No usable IPsec tunnels or mobile keys in the source config.")
	}
	if (p1 > 0 || srcConns > 0) && len(conns) == 0 {
		return fail("output-ipsec", "output", title, "IPsec tunnels were not written to OPNsense/Swanctl Connections.")
	}
	if (mobile > 0 || srcPSKs > 0) && len(psks) == 0 {
		return fail("output-ipsec", "output", title, "IPsec pre-shared keys were not kept under OPNsense/IPsec/preSharedKeys.")
	}
	phase2 := p2
	if phase2 == 0 {
		phase2 = srcChildren
	}
	return pass("output-ipsec", "output", title, fmt.Sprintf(
		"%d Connection(s), %d child SA(s) (from %d phase2), %d pre-shared key(s) under VPN → IPsec → Connections (OPNsense/Swanctl).",
		len(conns), len(children), phase2, len(psks)))
}

func countPfSenseIPsec(in map[string]any) (p1, p2, mobile int) {
	ipsec := xmlutil.Get(in, "ipsec")
	for _, raw := range xmlutil.AsArray(xmlutil.Get(ipsec, "phase1")) {
		if xmlutil.AsString(xmlutil.Map(raw)["remote-gateway"]) != "" {
			p1++
		}
	}
	for _, raw := range xmlutil.AsArray(xmlutil.Get(ipsec, "phase2")) {
		if xmlutil.AsString(xmlutil.Map(raw)["ikeid"]) != "" {
			p2++
		}
	}
	for _, raw := range xmlutil.AsArray(xmlutil.Get(ipsec, "mobilekey")) {
		k := xmlutil.Map(raw)
		if xmlutil.AsString(k["ident"]) != "" && xmlutil.AsString(k["pre-shared-key"]) != "" {
			mobile++
		}
	}
	return
}

func checkPPPs(ctx Context) Check {
	title := "PPP / PPPoE links"
	filter := func(list []any) []any {
		out := []any{}
		for _, raw := range list {
			m := xmlutil.Map(raw)
			if xmlutil.AsString(m["type"]) != "" || xmlutil.AsString(m["if"]) != "" || xmlutil.AsString(m["ports"]) != "" {
				out = append(out, m)
			}
		}
		return out
	}
	in := filter(xmlutil.AsArray(xmlutil.Get(pfsense(ctx), "ppps", "ppp")))
	if len(in) == 0 {
		return skip("output-ppps", "output", title, "No PPP/PPPoE links in the source config.")
	}
	out := filter(xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "ppps", "ppp")))
	if len(out) != len(in) {
		return fail("output-ppps", "output", title, fmt.Sprintf("Source had %d PPP link(s) but output has %d.", len(in), len(out)))
	}
	return pass("output-ppps", "output", title, fmt.Sprintf("%d PPP/PPPoE link(s) copied.", len(out)))
}

func checkSyslog(ctx Context) Check {
	title := "Syslog"
	in := xmlutil.Get(pfsense(ctx), "syslog")
	if xmlutil.IsEmptySection(in) {
		return skip("output-syslog", "output", title, "No syslog section in the source config.")
	}
	out := xmlutil.Map(xmlutil.Get(opnsense(ctx), "syslog"))
	if xmlutil.IsEmptySection(out) {
		return fail("output-syslog", "output", title, "Syslog settings were not copied.")
	}
	im := xmlutil.Map(in)
	remote := []string{}
	inRemote := []string{}
	for _, key := range []string{"remoteserver", "remoteserver2", "remoteserver3"} {
		if s := xmlutil.AsString(out[key]); s != "" {
			remote = append(remote, s)
		}
		if s := xmlutil.AsString(im[key]); s != "" {
			inRemote = append(inRemote, s)
		}
	}
	if len(inRemote) > 0 && len(remote) != len(inRemote) {
		return fail("output-syslog", "output", title, "Remote syslog server(s) from the source were not copied.")
	}
	nentries := xmlutil.AsString(out["nentries"])
	if nentries == "" {
		nentries = xmlutil.AsString(im["nentries"])
	}
	if nentries == "" {
		nentries = "default"
	}
	detail := "nentries=" + nentries
	if len(remote) > 0 {
		detail += fmt.Sprintf(", %d remote server(s)", len(remote))
	} else {
		detail += ", local only"
	}
	return pass("output-syslog", "output", title, "Syslog copied ("+detail+").")
}

func checkCron(ctx Context) Check {
	title := "Cron jobs"
	in := []any{}
	for _, raw := range xmlutil.AsArray(xmlutil.Get(pfsense(ctx), "cron", "item")) {
		if xmlutil.AsString(xmlutil.Map(raw)["command"]) != "" {
			in = append(in, raw)
		}
	}
	if len(in) == 0 {
		return skip("output-cron", "output", title, "No cron jobs in the source config.")
	}
	legacy := xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "cron", "item"))
	pfOnlyRe := regexp.MustCompile(`/etc/rc\.(update_bogons|dyndns|update_urltables)|/usr/local/pkg/`)
	for _, raw := range legacy {
		if pfOnlyRe.MatchString(xmlutil.AsString(xmlutil.Map(raw)["command"])) {
			return fail("output-cron", "output", title, "pfSense-only cron scripts were dumped. They will not run on OPNsense.")
		}
	}
	jobs := xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "OPNsense", "cron", "jobs", "job"))
	kept, omitted := 0, 0
	for _, raw := range in {
		action, reason := mapper.ClassifyCron(xmlutil.AsString(xmlutil.Map(raw)["command"]))
		if action != "" && reason == "" {
			kept++
		} else {
			omitted++
		}
	}
	if kept > 0 && len(jobs) == 0 {
		return fail("output-cron", "output", title, "Mappable cron jobs were not written to OPNsense/cron.")
	}
	for _, raw := range jobs {
		if xmlutil.AsString(xmlutil.Map(raw)["who"]) == "" {
			return fail("output-cron", "output", title, "cron job(s) are missing a user.")
		}
	}
	detail := fmt.Sprintf("%d OPNsense cron job(s)", len(jobs))
	if omitted > 0 {
		detail += fmt.Sprintf(", %d pfSense-only/system job(s) omitted", omitted)
	}
	return pass("output-cron", "output", title, detail+".")
}

func checkDynDNS(ctx Context) Check {
	title := "DynDNS → os-ddclient"
	in := []any{}
	for _, raw := range xmlutil.AsArray(xmlutil.Get(pfsense(ctx), "dyndnses", "dyndns")) {
		m := xmlutil.Map(raw)
		if xmlutil.AsString(m["type"]) != "" || xmlutil.AsString(m["host"]) != "" || xmlutil.AsString(m["username"]) != "" {
			in = append(in, m)
		}
	}
	if len(in) == 0 {
		return skip("output-dyndns", "output", title, "No DynDNS accounts in the source config.")
	}
	if xmlutil.Get(opnsense(ctx), "dyndnses") != nil {
		return fail("output-dyndns", "output", title, "Legacy <dyndnses> was dumped. OPNsense 26.7 expects OPNsense/DynDNS (os-ddclient).")
	}
	accounts := xmlutil.AsArray(xmlutil.Get(opnsense(ctx), "OPNsense", "DynDNS", "accounts", "account"))
	if len(accounts) != len(in) {
		return fail("output-dyndns", "output", title, fmt.Sprintf("Source had %d DynDNS account(s) but output has %d under OPNsense/DynDNS.", len(in), len(accounts)))
	}
	missing := 0
	for _, raw := range accounts {
		if xmlutil.AsString(xmlutil.Map(raw)["hostnames"]) == "" {
			missing++
		}
	}
	detail := fmt.Sprintf("%d account(s) in OPNsense/DynDNS. Install os-ddclient.", len(accounts))
	if missing > 0 {
		return warn("output-dyndns", "output", title, fmt.Sprintf("%s %d account(s) have no hostname.", detail, missing))
	}
	return pass("output-dyndns", "output", title, detail)
}

func checkOvpnWizard(ctx Context) Check {
	title := "OpenVPN wizard leftover"
	had := !xmlutil.IsEmptySection(xmlutil.Get(pfsense(ctx), "ovpnserver"))
	dumped := !xmlutil.IsEmptySection(xmlutil.Get(opnsense(ctx), "ovpnserver"))
	if dumped {
		return fail("output-ovpnwizard", "output", title, "pfSense <ovpnserver> wizard state was copied. That is not a live OpenVPN config and is not used by OPNsense 26.7.")
	}
	if !had {
		return skip("output-ovpnwizard", "output", title, "No pfSense OpenVPN wizard state in the source config.")
	}
	return pass("output-ovpnwizard", "output", title, "pfSense OpenVPN wizard state was omitted. Live servers/clients were mapped to Instances.")
}
