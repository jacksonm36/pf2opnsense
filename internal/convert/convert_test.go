package convert

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jacksonm36/pf2opnsense/internal/mapper"
	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func sample(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "sample-files", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func asArray(v any) []any {
	return xmlutil.AsArray(v)
}

func checkStatus(t *testing.T, result Result, id, want string) {
	t.Helper()
	for _, c := range result.Validation.Checks {
		if c.ID != id {
			continue
		}
		ok := c.Status == want || (want == "pass-or-warn" && (c.Status == "pass" || c.Status == "warn"))
		if !ok {
			t.Fatalf("check %s: got %s (%s), want %s", id, c.Status, c.Detail, want)
		}
		return
	}
	t.Fatalf("missing check %s", id)
}

func TestPfsense270(t *testing.T) {
	raw := sample(t, "pfsense-2.7.0.xml")
	parsed, err := xmlutil.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := mapper.Map(parsed, nil)
	if err != nil {
		t.Fatal(err)
	}
	root := xmlutil.Map(mapped.Root["opnsense"])
	if xmlutil.AsString(xmlutil.Get(root, "system", "hostname")) != "edge" {
		t.Fatalf("hostname: %v", xmlutil.Get(root, "system", "hostname"))
	}
	users := asArray(xmlutil.Get(root, "system", "user"))
	if xmlutil.AsString(xmlutil.Map(users[0])["name"]) != "root" {
		t.Fatal("uid 0 should be renamed to root")
	}
	if xmlutil.AsString(xmlutil.Get(root, "interfaces", "lan", "ipaddr")) != "192.168.1.1" {
		t.Fatal("lan ip")
	}
	if xmlutil.AsString(xmlutil.Get(root, "interfaces", "wan", "if")) != "em0" {
		t.Fatal("wan if")
	}
	vlan := xmlutil.Map(asArray(xmlutil.Get(root, "vlans", "vlan"))[0])
	if xmlutil.AsString(vlan["@_uuid"]) == "" || xmlutil.AsString(vlan["vlanif"]) != "vlan0.10" {
		t.Fatal("VLAN needs uuid and OPNsense vlan0.tag device name")
	}
	rules := asArray(xmlutil.Get(root, "OPNsense", "Firewall", "Filter", "rules", "rule"))
	if len(rules) != 3 {
		t.Fatalf("expected 3 MVC rules, got %d", len(rules))
	}
	if xmlutil.AsString(xmlutil.Map(rules[0])["source_net"]) != "lan" {
		t.Fatal("lan source")
	}
	aliases := asArray(xmlutil.Get(root, "OPNsense", "Firewall", "Alias", "aliases", "alias"))
	content := xmlutil.AsString(xmlutil.Map(aliases[0])["content"])
	if !strings.Contains(content, "192.168.1.10") {
		t.Fatal("alias content")
	}
	if !strings.Contains(content, "\n") {
		t.Fatal("alias newline separator")
	}
	ranges := asArray(xmlutil.Get(root, "dnsmasq", "dhcp_ranges"))
	if xmlutil.AsString(xmlutil.Map(ranges[0])["start_addr"]) != "192.168.1.100" {
		t.Fatal("dhcp range")
	}
	if xmlutil.AsString(xmlutil.Map(ranges[0])["@_uuid"]) == "" {
		t.Fatal("dhcp_ranges need uuid so OPNsense can delete them")
	}
	hosts := asArray(xmlutil.Get(root, "dnsmasq", "hosts"))
	if len(hosts) == 0 || xmlutil.AsString(xmlutil.Map(hosts[0])["@_uuid"]) == "" {
		t.Fatal("dnsmasq hosts need uuid so OPNsense can delete them")
	}
	gws := asArray(xmlutil.Get(root, "OPNsense", "Gateways", "gateway_item"))
	if xmlutil.AsString(xmlutil.Map(gws[0])["weight"]) != "1" {
		t.Fatal("gateway weight")
	}
	if xmlutil.Get(root, "installedpackages") != nil {
		t.Fatal("2.7.0 fixture has no packages")
	}
	filt := xmlutil.Map(root["filter"])
	if filt == nil || len(filt) != 0 {
		t.Fatalf("legacy filter should be empty, got %#v", filt)
	}

	out := Run("pfsense-2.7.0.xml", raw)
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("pfSense 2.7.0", out))
	}
	if out.Validation.Errors != 0 {
		t.Fatal("2.7.0 should have no failing checks")
	}
	if out.XML == "" || !strings.Contains(out.XML, "<opnsense>") {
		t.Fatal("downloadable XML is produced after validators pass")
	}
	if strings.Contains(out.XML, "<pfsense>") {
		t.Fatal("downloadable XML is OPNsense, not pfSense")
	}
	if !strings.Contains(out.XML, "\n") || !strings.Contains(out.XML, "192.168.1.10") {
		t.Fatal("pretty XML should keep alias addresses")
	}
	if !strings.Contains(out.XML, `vlanif>vlan0.10`) || !strings.Contains(out.XML, `<vlan uuid="`) {
		t.Fatal("VLAN uuid and vlan0.tag device name required for OPNsense 26.7")
	}
}

func TestKeaDHCP(t *testing.T) {
	raw := sample(t, "pfsense-2.7.0.xml")
	parsed, err := xmlutil.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := mapper.Map(parsed, &mapper.Options{DhcpBackend: mapper.DhcpKea})
	if err != nil {
		t.Fatal(err)
	}
	root := xmlutil.Map(mapped.Root["opnsense"])
	if xmlutil.Get(root, "dnsmasq", "dhcp_ranges") != nil {
		t.Fatal("Kea mode must not emit dnsmasq DHCP ranges")
	}
	subs := asArray(xmlutil.Get(root, "OPNsense", "Kea", "dhcp4", "subnets", "subnet4"))
	if len(subs) != 1 {
		t.Fatalf("Kea subnets: got %d", len(subs))
	}
	sub := xmlutil.Map(subs[0])
	if xmlutil.AsString(sub["subnet"]) != "192.168.1.0/24" {
		t.Fatalf("Kea CIDR: %s", xmlutil.AsString(sub["subnet"]))
	}
	if xmlutil.AsString(sub["pools"]) != "192.168.1.100-192.168.1.199" {
		t.Fatalf("Kea pool: %s", xmlutil.AsString(sub["pools"]))
	}
	res := asArray(xmlutil.Get(root, "OPNsense", "Kea", "dhcp4", "reservations", "reservation"))
	if len(res) != 1 || xmlutil.AsString(xmlutil.Map(res[0])["ip_address"]) != "192.168.1.20" {
		t.Fatal("Kea reservation for printer")
	}
	if xmlutil.AsString(xmlutil.Map(res[0])["hw_address"]) != "aa:bb:cc:dd:ee:ff" {
		t.Fatal("Kea MAC")
	}
	if xmlutil.AsString(xmlutil.Get(root, "OPNsense", "Kea", "dhcp4", "general", "enabled")) != "1" {
		t.Fatal("Kea enabled")
	}

	out := Run("pfsense-2.7.0.xml", raw, &mapper.Options{DhcpBackend: mapper.DhcpKea})
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("Kea DHCP", out))
	}
	checkStatus(t, out, "output-dhcp", "pass")
	if !strings.Contains(out.XML, "<Kea>") || !strings.Contains(out.XML, "<subnet4") {
		t.Fatal("Kea MVC XML present")
	}
	if strings.Contains(out.XML, "<dhcp_ranges>") {
		t.Fatal("dnsmasq dhcp_ranges must not appear in Kea mode")
	}
}

func TestComplex(t *testing.T) {
	raw := sample(t, "complex-pfsense.xml")
	parsed, err := xmlutil.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := mapper.Map(parsed, nil)
	if err != nil {
		t.Fatal(err)
	}
	root := xmlutil.Map(mapped.Root["opnsense"])
	if root["openvpn"] != nil {
		t.Fatal("legacy OpenVPN section must not be written")
	}
	instances := asArray(xmlutil.Get(root, "OPNsense", "OpenVPN", "Instances", "Instance"))
	if len(instances) != 2 {
		t.Fatalf("OpenVPN Instances: got %d", len(instances))
	}
	foundTun, foundGw, foundTap := false, false, false
	for _, rawInst := range instances {
		inst := xmlutil.Map(rawInst)
		if xmlutil.AsString(inst["role"]) == "server" && xmlutil.AsString(inst["server"]) == "10.2.1.0/24" {
			foundTun = true
		}
		if xmlutil.AsString(inst["vpnid"]) == "2" && xmlutil.AsString(inst["redirect_gateway"]) == "def1" {
			foundGw = true
		}
		if xmlutil.AsString(inst["vpnid"]) == "1" && xmlutil.AsString(inst["redirect_gateway"]) == "" {
			foundTap = true
		}
	}
	if !foundTun {
		t.Fatal("tun tunnel mapped to Instance server")
	}
	if !foundGw {
		t.Fatal("tun redirect gateway")
	}
	if !foundTap {
		t.Fatal("tap without empty gwredir")
	}
	if len(asArray(xmlutil.Get(root, "OPNsense", "OpenVPN", "StaticKeys", "StaticKey"))) < 1 {
		t.Fatal("TLS static keys")
	}
	overwrites := asArray(xmlutil.Get(root, "OPNsense", "OpenVPN", "Overwrites", "Overwrite"))
	if len(overwrites) != 3 {
		t.Fatalf("MVC OpenVPN user overwrites: got %d", len(overwrites))
	}
	foundCN := false
	for _, rawOW := range overwrites {
		if xmlutil.AsString(xmlutil.Map(rawOW)["common_name"]) == "Lolercoaster" {
			foundCN = true
		}
	}
	if !foundCN {
		t.Fatal("CSC common name")
	}
	if xmlutil.Get(root, "installedpackages") == nil {
		t.Fatal("packages copied")
	}
	if mapped.Report.Stats.OpenvpnUsers != 3 {
		t.Fatalf("openvpn user stats: %d", mapped.Report.Stats.OpenvpnUsers)
	}
	if mapped.Report.Stats.Packages == 0 {
		t.Fatal("package stats")
	}
	foundUserCert := false
	for _, rawCert := range asArray(root["cert"]) {
		if xmlutil.AsString(xmlutil.Map(rawCert)["type"]) == "user" {
			foundUserCert = true
		}
	}
	if !foundUserCert {
		t.Fatal("user certs copied")
	}
	if root["ovpnserver"] != nil {
		t.Fatal("OpenVPN wizard state must not be copied")
	}
	if root["dyndnses"] != nil {
		t.Fatal("legacy dyndnses must not be copied")
	}
	accounts := asArray(xmlutil.Get(root, "OPNsense", "DynDNS", "accounts", "account"))
	if len(accounts) < 1 {
		t.Fatal("DynDNS MVC accounts")
	}
	if xmlutil.AsString(xmlutil.Map(accounts[0])["service"]) != "no-ip" {
		t.Fatalf("noip mapped to no-ip, got %s", xmlutil.AsString(xmlutil.Map(accounts[0])["service"]))
	}
	if len(asArray(root["ca"])) < 1 {
		t.Fatal("CAs copied")
	}
	nentries := xmlutil.AsString(xmlutil.Get(root, "syslog", "nentries"))
	if nentries != "1000" {
		t.Fatalf("syslog copied: nentries=%s", nentries)
	}
	if strings.Contains(xmlutil.Write(mapped.Root, true), "rc.update_bogons") {
		t.Fatal("pfSense bogons cron must not be copied")
	}
	if xmlutil.Get(root, "ipsec", "phase1") != nil && xmlutil.AsString(xmlutil.Get(root, "ipsec", "phase1", "remote-gateway")) != "" {
		t.Fatal("legacy IPsec phase1 must not be written")
	}
	if xmlutil.Get(root, "OPNsense", "IPsec", "preSharedKeys", "preSharedKey") == nil {
		t.Fatal("mobile IPsec PSK should be mapped to preSharedKeys")
	}

	out := Run("complex-pfsense.xml", raw)
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("complex pfSense", out))
	}
	checkStatus(t, out, "input-revision", "warn")
	checkStatus(t, out, "output-openvpn", "pass")
	checkStatus(t, out, "output-trust", "pass-or-warn")
	checkStatus(t, out, "output-dyndns", "pass")
	checkStatus(t, out, "output-ovpnwizard", "pass")
	checkStatus(t, out, "output-cron", "pass")
	checkStatus(t, out, "output-ipsec", "pass")
	checkStatus(t, out, "output-syslog", "pass")
	if strings.Contains(out.XML, "<ovpnserver>") {
		t.Fatal("wizard XML omitted")
	}
	if strings.Contains(out.XML, "<dyndnses>") {
		t.Fatal("legacy dyndnses omitted")
	}
	if !strings.Contains(out.XML, "<DynDNS>") {
		t.Fatal("DynDNS MVC XML present")
	}
}

func TestOtherSamples(t *testing.T) {
	for _, name := range []string{"pfsense-3.xml", "pfsense.xml"} {
		parsed, err := xmlutil.Parse([]byte(sample(t, name)))
		if err != nil {
			t.Fatalf("%s parse: %v", name, err)
		}
		mapped, err := mapper.Map(parsed, nil)
		if err != nil {
			t.Fatalf("%s convert: %v", name, err)
		}
		if xmlutil.Get(mapped.Root, "opnsense", "OPNsense", "Firewall") == nil {
			t.Fatalf("%s has MVC firewall", name)
		}
	}
}

func TestOpnsenseInputPassThrough(t *testing.T) {
	out := Run("opnsense.xml", sample(t, "opnsense.xml"))
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("OPNsense-as-input", out))
	}
	checkStatus(t, out, "input-root", "pass")
	if !strings.Contains(out.XML, "<opnsense>") {
		t.Fatal("OPNsense input should produce OPNsense XML")
	}
	if !strings.Contains(out.XML, "my-opnsense-firewall") {
		t.Fatal("hostname preserved")
	}
}

func TestOpnDnsmasqToKeaAndBack(t *testing.T) {
	raw := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>edge</hostname>
    <domain>lab.local</domain>
    <user><name>root</name><uid>0</uid></user>
  </system>
  <interfaces>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><descr>LAN</descr></lan>
  </interfaces>
  <dnsmasq>
    <enable>1</enable>
    <interface>lan</interface>
    <dhcp_ranges>
      <interface>lan</interface>
      <start_addr>192.168.1.100</start_addr>
      <end_addr>192.168.1.199</end_addr>
    </dhcp_ranges>
    <hosts>
      <host>printer</host>
      <ip>192.168.1.20</ip>
      <hwaddr>aa:bb:cc:dd:ee:ff</hwaddr>
      <descr>Office printer</descr>
    </hosts>
  </dnsmasq>
</opnsense>`
	toKea := Run("opn.xml", raw, &mapper.Options{DhcpBackend: mapper.DhcpKea})
	if !toKea.Validation.CanDownload {
		t.Fatal(failSummary("OPNsense dnsmasq→Kea", toKea))
	}
	checkStatus(t, toKea, "output-dhcp", "pass")
	if !strings.Contains(toKea.XML, "<Kea>") || !strings.Contains(toKea.XML, "192.168.1.0/24") {
		t.Fatal("Kea subnet from dnsmasq range")
	}
	if !strings.Contains(toKea.XML, "192.168.1.20") || !strings.Contains(toKea.XML, "aa:bb:cc:dd:ee:ff") {
		t.Fatal("Kea reservation from dnsmasq host")
	}
	if strings.Contains(toKea.XML, "<dhcp_ranges>") {
		t.Fatal("dnsmasq DHCP ranges removed after Kea conversion")
	}

	back := Run("kea.xml", toKea.XML, &mapper.Options{DhcpBackend: mapper.DhcpDnsmasq})
	if !back.Validation.CanDownload {
		t.Fatal(failSummary("OPNsense Kea→dnsmasq", back))
	}
	checkStatus(t, back, "output-dhcp", "pass")
	if !strings.Contains(back.XML, "<dhcp_ranges") || !strings.Contains(back.XML, "192.168.1.100") {
		t.Fatal("dnsmasq range restored from Kea")
	}
	if !strings.Contains(back.XML, "printer") || !strings.Contains(back.XML, "aa:bb:cc:dd:ee:ff") {
		t.Fatal("dnsmasq host restored from Kea reservation")
	}
	if strings.Contains(back.XML, "<enabled>1</enabled>") && strings.Contains(back.XML, "<Kea>") {
		parsed, err := xmlutil.Parse([]byte(back.XML))
		if err != nil {
			t.Fatal(err)
		}
		root := xmlutil.Map(parsed["opnsense"])
		if xmlutil.AsString(xmlutil.Get(root, "OPNsense", "Kea", "dhcp4", "general", "enabled")) == "1" {
			t.Fatal("Kea must be disabled after converting to dnsmasq")
		}
	}
}

func TestRejectGarbageXML(t *testing.T) {
	out := Run("broken.xml", "this is not xml")
	if out.Validation.CanDownload {
		t.Fatal("invalid XML is blocked")
	}
	if out.XML != "" {
		t.Fatal("invalid XML produces no download")
	}
	checkStatus(t, out, "input-xml", "fail")
	for _, c := range out.Validation.Checks {
		if c.ID != "input-xml" && c.Status != "skip" {
			t.Fatalf("later check %s should be skipped, got %s", c.ID, c.Status)
		}
	}
}

func TestIPsecConnectionAndCronOmit(t *testing.T) {
	raw := `<?xml version="1.0"?>
<pfsense>
  <version>22.9</version>
  <system>
    <hostname>edge</hostname>
    <user><name>admin</name><uid>0</uid></user>
  </system>
  <interfaces>
    <wan><if>em0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <ipsec>
    <phase1>
      <ikeid>1</ikeid>
      <iketype>ikev2</iketype>
      <interface>wan</interface>
      <remote-gateway>203.0.113.1</remote-gateway>
      <myid_type>address</myid_type>
      <myid_data>198.51.100.1</myid_data>
      <peerid_type>peeraddress</peerid_type>
      <authentication_method>pre_shared_key</authentication_method>
      <pre-shared-key>secret</pre-shared-key>
      <lifetime>28800</lifetime>
      <hash-algorithm>sha256</hash-algorithm>
      <dhgroup>14</dhgroup>
      <encryption-algorithm><name>aes</name><keylen>256</keylen></encryption-algorithm>
      <descr>office</descr>
    </phase1>
    <phase2>
      <ikeid>1</ikeid>
      <mode>tunnel</mode>
      <reqid>1</reqid>
      <lifetime>3600</lifetime>
      <encryption-algorithm-option><name>aes</name><keylen>256</keylen></encryption-algorithm-option>
      <hash-algorithm-option>hmac_sha256</hash-algorithm-option>
      <pfsgroup>14</pfsgroup>
      <localid><type>network</type><address>192.168.1.0</address><netbits>24</netbits></localid>
      <remoteid><type>network</type><address>10.0.0.0</address><netbits>24</netbits></remoteid>
      <descr>lan-to-lan</descr>
    </phase2>
  </ipsec>
  <cron>
    <item><minute>1</minute><hour>3</hour><mday>1</mday><month>*</month><wday>*</wday><who>root</who><command>/usr/bin/nice -n20 /etc/rc.update_bogons.sh</command></item>
    <item><minute>*</minute><hour>*</hour><mday>*</mday><month>*</month><wday>*</wday><who>root</who><command>/usr/local/sbin/configctl firmware poll</command></item>
  </cron>
</pfsense>`
	out := Run("ipsec.xml", raw)
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("ipsec sample", out))
	}
	checkStatus(t, out, "output-ipsec", "pass")
	checkStatus(t, out, "output-cron", "pass")
	if strings.Contains(out.XML, "<phase1>") {
		t.Fatal("legacy phase1 must not be in output")
	}
	if !strings.Contains(out.XML, "<Connection") || !strings.Contains(out.XML, "203.0.113.1") {
		t.Fatal("Swanctl Connection should include remote gateway")
	}
	if !strings.Contains(out.XML, "192.168.1.0/24") || !strings.Contains(out.XML, "10.0.0.0/24") {
		t.Fatal("child traffic selectors")
	}
	if strings.Contains(out.XML, "rc.update_bogons") {
		t.Fatal("bogons cron omitted")
	}
	if !strings.Contains(out.XML, "firmware poll") {
		t.Fatal("configctl cron should be mapped")
	}
	if !strings.Contains(out.XML, "<ident>198.51.100.1</ident>") {
		t.Fatal("PSK local ident should be pfSense myid, not the remote gateway")
	}
	if !strings.Contains(out.XML, "<remote_ident>203.0.113.1</remote_ident>") {
		t.Fatal("PSK remote ident should be the peer")
	}
	parsed, err := xmlutil.Parse([]byte(out.XML))
	if err != nil {
		t.Fatal(err)
	}
	root := xmlutil.Map(parsed["opnsense"])
	if xmlutil.Get(root, "OPNsense", "IPsec", "Swanctl") != nil {
		t.Fatal("Swanctl must be a sibling of IPsec, not nested under it")
	}
	if xmlutil.Get(root, "OPNsense", "Swanctl", "Connections", "Connection") == nil {
		t.Fatal("Connections must be at OPNsense/Swanctl")
	}
	if xmlutil.Get(root, "OPNsense", "IPsec", "preSharedKeys", "preSharedKey") == nil {
		t.Fatal("PSK remains under OPNsense/IPsec")
	}
}

func TestIPsecPSKDoesNotCopyRemoteToLocalIdent(t *testing.T) {
	raw := `<?xml version="1.0"?>
<pfsense>
  <version>22.9</version>
  <system>
    <hostname>edge</hostname>
    <user><name>admin</name><uid>0</uid></user>
  </system>
  <interfaces>
    <wan><if>em0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <ipsec>
    <phase1>
      <ikeid>1</ikeid>
      <iketype>ikev2</iketype>
      <interface>wan</interface>
      <remote-gateway>vpn-peer.example.net</remote-gateway>
      <myid_type>myaddress</myid_type>
      <peerid_type>peeraddress</peerid_type>
      <authentication_method>pre_shared_key</authentication_method>
      <pre-shared-key>secret</pre-shared-key>
      <lifetime>28800</lifetime>
      <hash-algorithm>sha256</hash-algorithm>
      <dhgroup>15</dhgroup>
      <encryption-algorithm><name>aes</name><keylen>256</keylen></encryption-algorithm>
      <descr>site-to-site</descr>
    </phase1>
    <phase2>
      <ikeid>1</ikeid>
      <mode>tunnel</mode>
      <reqid>1</reqid>
      <lifetime>3600</lifetime>
      <encryption-algorithm-option><name>aes</name><keylen>256</keylen></encryption-algorithm-option>
      <hash-algorithm-option>hmac_sha1</hash-algorithm-option>
      <pfsgroup>14</pfsgroup>
      <localid><type>network</type><address>192.168.1.0</address><netbits>24</netbits></localid>
      <remoteid><type>network</type><address>10.0.0.0</address><netbits>24</netbits></remoteid>
    </phase2>
  </ipsec>
</pfsense>`
	out := Run("ipsec-psk.xml", raw)
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("ipsec PSK ident", out))
	}
	if strings.Contains(out.XML, "<ident>vpn-peer.example.net</ident>") {
		t.Fatal("PSK local ident must not be filled with the remote gateway")
	}
	if !strings.Contains(out.XML, "<remote_ident>vpn-peer.example.net</remote_ident>") {
		t.Fatal("PSK remote ident should be the peer hostname")
	}
}

func TestOpnLiftsNestedSwanctl(t *testing.T) {
	raw := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>edge</hostname>
    <user><name>root</name><uid>0</uid></user>
  </system>
  <interfaces>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <OPNsense>
    <IPsec>
      <general><enabled>1</enabled></general>
      <preSharedKeys>
        <preSharedKey uuid="aaa">
          <ident></ident>
          <remote_ident>vpn-peer.example.net</remote_ident>
          <keyType>PSK</keyType>
          <Key>secret</Key>
          <description>site-to-site</description>
        </preSharedKey>
      </preSharedKeys>
      <Swanctl version="1.0.0">
        <Connections>
          <Connection uuid="bbb">
            <enabled>1</enabled>
            <remote_addrs>vpn-peer.example.net</remote_addrs>
            <description>site-to-site</description>
          </Connection>
        </Connections>
        <children>
          <child uuid="ccc">
            <enabled>1</enabled>
            <connection>bbb</connection>
            <local_ts>192.168.116.0/22</local_ts>
            <remote_ts>10.1.2.0/24</remote_ts>
            <description>EG_LAN</description>
          </child>
        </children>
      </Swanctl>
    </IPsec>
  </OPNsense>
</opnsense>`
	out := Run("nested-swanctl.xml", raw)
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("lift nested Swanctl", out))
	}
	parsed, err := xmlutil.Parse([]byte(out.XML))
	if err != nil {
		t.Fatal(err)
	}
	root := xmlutil.Map(parsed["opnsense"])
	if xmlutil.Get(root, "OPNsense", "IPsec", "Swanctl") != nil {
		t.Fatal("nested IPsec/Swanctl must be removed")
	}
	conns := asArray(xmlutil.Get(root, "OPNsense", "Swanctl", "Connections", "Connection"))
	if len(conns) == 0 || xmlutil.AsString(xmlutil.Map(conns[0])["description"]) != "site-to-site" {
		t.Fatal("Connection must land at OPNsense/Swanctl")
	}
	if xmlutil.Get(root, "OPNsense", "IPsec", "preSharedKeys", "preSharedKey") == nil {
		t.Fatal("PSK stays under OPNsense/IPsec")
	}
	found := false
	for _, n := range out.Notes {
		if strings.Contains(n, "OPNsense/Swanctl") {
			found = true
		}
	}
	if !found {
		t.Fatal("conversion notes should mention the Swanctl remount")
	}
	checkStatus(t, out, "output-ipsec", "pass")
}

func failSummary(label string, result Result) string {
	failed := []string{}
	for _, c := range result.Validation.Checks {
		if c.Status == "fail" {
			failed = append(failed, c.ID+": "+c.Detail)
		}
	}
	return label + " should be downloadable. Failures: " + strings.Join(failed, "; ")
}

func TestOvpnFallbackSingleCipherAndEmptyShaper(t *testing.T) {
	raw := `<?xml version="1.0"?>
<pfsense>
  <version>22.9</version>
  <system>
    <hostname>edge</hostname>
    <user><name>admin</name><uid>0</uid></user>
  </system>
  <interfaces>
    <wan><if>em0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <shaper></shaper>
  <dnshaper></dnshaper>
  <openvpn>
    <openvpn-server>
      <vpnid>1</vpnid>
      <mode>server_tls</mode>
      <protocol>UDP4</protocol>
      <dev_mode>tun</dev_mode>
      <interface>wan</interface>
      <local_port>1194</local_port>
      <description>Remote access</description>
      <tunnel_network>10.2.1.0/24</tunnel_network>
      <crypto>AES-256-GCM,AES-128-GCM,CHACHA20-POLY1305</crypto>
      <ncp-ciphers>AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305</ncp-ciphers>
      <data-ciphers>AES-256-GCM,AES-128-GCM,CHACHA20-POLY1305</data-ciphers>
    </openvpn-server>
  </openvpn>
</pfsense>`
	out := Run("ovpn.xml", raw)
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("ovpn fallback", out))
	}
	if !strings.Contains(out.XML, "<data-ciphers-fallback>AES-256-GCM</data-ciphers-fallback>") {
		t.Fatal("fallback must be a single cipher")
	}
	if strings.Contains(out.XML, "<data-ciphers-fallback>AES-256-GCM,AES-128-GCM") {
		t.Fatal("fallback must not be a cipher list")
	}
	for _, n := range out.Notes {
		if strings.Contains(n, "Traffic shaping") {
			t.Fatalf("empty shaper must not warn: %s", n)
		}
	}
}

func TestVLANPrefixAndInterfaceRename(t *testing.T) {
	raw := `<?xml version="1.0"?>
<pfsense>
  <version>22.9</version>
  <system>
    <hostname>edge</hostname>
    <user><name>admin</name><uid>0</uid></user>
  </system>
  <interfaces>
    <wan><if>em0</if><ipaddr>dhcp</ipaddr></wan>
    <opt1><if>re0.10</if><ipaddr>10.10.10.1</ipaddr><subnet>24</subnet><descr>Kliens</descr><enable/></opt1>
  </interfaces>
  <vlans>
    <vlan>
      <if>re0</if>
      <tag>10</tag>
      <vlanif>re0.10</vlanif>
      <descr>Kliens</descr>
    </vlan>
  </vlans>
</pfsense>`
	out := Run("vlan.xml", raw)
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("vlan prefix", out))
	}
	checkStatus(t, out, "output-vlans", "pass")
	if strings.Contains(out.XML, ">re0.10<") {
		t.Fatal("pfSense re0.10 device name must not remain")
	}
	if !strings.Contains(out.XML, ">vlan0.10<") {
		t.Fatal("OPNsense vlan0.10 device name")
	}
}

func TestOpnExtraDnsmasqRangesToKea(t *testing.T) {
	raw := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>edge</hostname>
    <user><name>root</name><uid>0</uid></user>
  </system>
  <interfaces>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><descr>LAN</descr></lan>
  </interfaces>
  <dnsmasq>
    <enable>1</enable>
    <interface>lan</interface>
    <dhcp_ranges>
      <interface>lan</interface>
      <start_addr>192.168.1.50</start_addr>
      <end_addr>192.168.1.99</end_addr>
    </dhcp_ranges>
    <dhcp_ranges>
      <interface>lan</interface>
      <start_addr>192.168.1.200</start_addr>
      <end_addr>192.168.1.220</end_addr>
    </dhcp_ranges>
  </dnsmasq>
</opnsense>`
	out := Run("extra-ranges.xml", raw, &mapper.Options{DhcpBackend: mapper.DhcpKea})
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("extra dnsmasq ranges", out))
	}
	if !strings.Contains(out.XML, "192.168.1.50-192.168.1.99") {
		t.Fatal("first LAN pool missing from Kea")
	}
	if !strings.Contains(out.XML, "192.168.1.200-192.168.1.220") {
		t.Fatal("second LAN pool dropped when remapping to Kea")
	}
}

func TestOpnDualDhcpKeepsKeaReservations(t *testing.T) {
	raw := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>edge</hostname>
    <user><name>root</name><uid>0</uid></user>
  </system>
  <interfaces>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><descr>LAN</descr></lan>
  </interfaces>
  <dnsmasq>
    <enable>1</enable>
    <interface>lan</interface>
    <dhcp_ranges>
      <interface>lan</interface>
      <start_addr>192.168.1.100</start_addr>
      <end_addr>192.168.1.199</end_addr>
    </dhcp_ranges>
  </dnsmasq>
  <OPNsense>
    <Kea>
      <dhcp4>
        <general>
          <enabled>1</enabled>
          <interfaces>lan</interfaces>
        </general>
        <subnets>
          <subnet4 uuid="sub1">
            <subnet>192.168.1.0/24</subnet>
            <description>lan</description>
            <pools>192.168.1.10-192.168.1.20</pools>
          </subnet4>
        </subnets>
        <reservations>
          <reservation uuid="res1">
            <subnet>sub1</subnet>
            <ip_address>192.168.1.50</ip_address>
            <hw_address>aa:bb:cc:dd:ee:ff</hw_address>
            <hostname>kea-only</hostname>
          </reservation>
        </reservations>
      </dhcp4>
    </Kea>
  </OPNsense>
</opnsense>`
	out := Run("dual-dhcp.xml", raw, &mapper.Options{DhcpBackend: mapper.DhcpKea})
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("dual DHCP keep Kea", out))
	}
	if !strings.Contains(out.XML, "192.168.1.50") || !strings.Contains(out.XML, "kea-only") {
		t.Fatal("Kea-only reservation must be kept when both backends exist")
	}
	if !strings.Contains(out.XML, "192.168.1.10-192.168.1.20") {
		t.Fatal("existing Kea pool must be kept")
	}
	if !strings.Contains(out.XML, "192.168.1.100-192.168.1.199") {
		t.Fatal("dnsmasq-only pool should merge into Kea")
	}
	if strings.Contains(out.XML, "<dhcp_ranges>") {
		t.Fatal("dnsmasq DHCP ranges must be stripped when Kea is selected")
	}
}

func TestDnsmasqHostUUIDsKeepDuplicateIPs(t *testing.T) {
	raw := `<?xml version="1.0"?>
<pfsense>
  <version>22.9</version>
  <system>
    <hostname>edge</hostname>
    <user><name>admin</name><uid>0</uid></user>
  </system>
  <interfaces>
    <wan><if>em0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><if>em1</if><ipaddr>192.168.116.254</ipaddr><subnet>23</subnet></lan>
  </interfaces>
  <dhcpd>
    <dhcpddata><foo>bar</foo></dhcpddata>
    <lan>
      <enable></enable>
      <range>
        <from>192.168.116.1</from>
        <to>192.168.116.244</to>
      </range>
      <staticmap>
        <mac>aa:bb:cc:dd:ee:01</mac>
        <ipaddr>192.168.116.253</ipaddr>
        <hostname>host-a</hostname>
      </staticmap>
      <staticmap>
        <mac>aa:bb:cc:dd:ee:02</mac>
        <ipaddr>192.168.116.253</ipaddr>
        <hostname>host-b</hostname>
      </staticmap>
    </lan>
  </dhcpd>
</pfsense>`
	out := Run("dup-ip.xml", raw)
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("dnsmasq host uuid", out))
	}
	if !strings.Contains(out.XML, "host-a") || !strings.Contains(out.XML, "host-b") {
		t.Fatal("duplicate IPs must both be kept")
	}
	if strings.Contains(out.XML, "dhcpddata") {
		t.Fatal("dhcpddata must not appear in dnsmasq interface list")
	}
	parsed, err := xmlutil.Parse([]byte(out.XML))
	if err != nil {
		t.Fatal(err)
	}
	root := xmlutil.Map(parsed["opnsense"])
	hosts := asArray(xmlutil.Get(root, "dnsmasq", "hosts"))
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts, got %d", len(hosts))
	}
	for i, rawH := range hosts {
		if xmlutil.AsString(xmlutil.Map(rawH)["@_uuid"]) == "" {
			t.Fatalf("host %d missing uuid", i)
		}
	}
	ranges := asArray(xmlutil.Get(root, "dnsmasq", "dhcp_ranges"))
	if len(ranges) == 0 || xmlutil.AsString(xmlutil.Map(ranges[0])["@_uuid"]) == "" {
		t.Fatal("dhcp_ranges missing uuid")
	}
}

func TestOpnAssignsMissingDnsmasqUUIDs(t *testing.T) {
	raw := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>edge</hostname>
    <user><name>root</name><uid>0</uid></user>
  </system>
  <interfaces>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <dnsmasq>
    <enable>1</enable>
    <interface>dhcpddata,lan</interface>
    <dhcp_ranges>
      <interface>lan</interface>
      <start_addr>192.168.1.100</start_addr>
      <end_addr>192.168.1.199</end_addr>
    </dhcp_ranges>
    <hosts>
      <host>printer</host>
      <ip>192.168.1.20</ip>
      <hwaddr>aa:bb:cc:dd:ee:ff</hwaddr>
    </hosts>
  </dnsmasq>
</opnsense>`
	out := Run("opn-no-uuid.xml", raw)
	if !out.Validation.CanDownload {
		t.Fatal(failSummary("OPNsense dnsmasq uuid", out))
	}
	parsed, err := xmlutil.Parse([]byte(out.XML))
	if err != nil {
		t.Fatal(err)
	}
	root := xmlutil.Map(parsed["opnsense"])
	hosts := asArray(xmlutil.Get(root, "dnsmasq", "hosts"))
	if len(hosts) == 0 || xmlutil.AsString(xmlutil.Map(hosts[0])["@_uuid"]) == "" {
		t.Fatal("OPNsense input hosts must get a uuid")
	}
	ranges := asArray(xmlutil.Get(root, "dnsmasq", "dhcp_ranges"))
	if len(ranges) == 0 || xmlutil.AsString(xmlutil.Map(ranges[0])["@_uuid"]) == "" {
		t.Fatal("OPNsense input dhcp_ranges must get a uuid")
	}
	iface := xmlutil.AsString(xmlutil.Get(root, "dnsmasq", "interface"))
	if strings.Contains(iface, "dhcpddata") {
		t.Fatalf("dhcpddata left in interface: %s", iface)
	}
}
