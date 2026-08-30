package validate

import (
	"strings"
	"testing"

	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

func TestCheckIPsecModel(t *testing.T) {
	swanctl := func(body string) string {
		return `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>edge</hostname>
    <user><name>root</name><uid>0</uid></user>
  </system>
  <interfaces>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <OPNsense>
    <IPsec><general><enabled>1</enabled></general></IPsec>
    <Swanctl version="1.0.0">` + body + `</Swanctl>
  </OPNsense>
</opnsense>`
	}
	conn := `<Connections><Connection uuid="c1"><enabled>1</enabled><proposals>aes256-sha256-modp3072</proposals>
      <version>2</version><remote_addrs>203.0.113.1</remote_addrs><description>office</description></Connection></Connections>`

	cases := []struct {
		name, body, status, detail string
	}{
		{
			name: "valid",
			body: conn + `<children><child uuid="h1"><connection>c1</connection><mode>tunnel</mode>
      <esp_proposals>aes256-sha256-modp3072</esp_proposals><local_ts>192.168.1.0/24</local_ts>
      <remote_ts>10.0.0.0/24</remote_ts><description>lan</description></child></children>`,
			status: "pass",
		},
		{
			name: "auto keylen leaks into the proposal",
			body: conn + `<children><child uuid="h1"><connection>c1</connection><mode>tunnel</mode>
      <esp_proposals>aesauto-sha1</esp_proposals><description>lan</description></child></children>`,
			status: "fail",
			detail: "aesauto",
		},
		{
			name: "child orphaned from its connection",
			body: conn + `<children><child uuid="h1"><connection>missing</connection><mode>tunnel</mode>
      <esp_proposals>aes256-sha256-modp3072</esp_proposals><description>lan</description></child></children>`,
			status: "fail",
			detail: "not in the output",
		},
		{
			name: "mode outside the OPNsense option list",
			body: conn + `<children><child uuid="h1"><connection>c1</connection><mode>vti</mode>
      <esp_proposals>aes256-sha256-modp3072</esp_proposals><description>lan</description></child></children>`,
			status: "fail",
			detail: `mode "vti"`,
		},
		{
			name: "selector carries host bits",
			body: conn + `<children><child uuid="h1"><connection>c1</connection><mode>tunnel</mode>
      <esp_proposals>aes256-sha256-modp3072</esp_proposals><local_ts>192.168.1.1/24</local_ts>
      <description>lan</description></child></children>`,
			status: "warn",
			detail: "host bits",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := xmlutil.Parse([]byte(swanctl(tc.body)))
			if err != nil {
				t.Fatal(err)
			}
			root := map[string]any{"opnsense": parsed["opnsense"]}
			report := Run(Context{
				FileName:    "swanctl.xml",
				RawText:     swanctl(tc.body),
				ParsedInput: parsed,
				MappedRoot:  root,
				OutputXML:   xmlutil.Write(root, true),
			})
			for _, c := range report.Checks {
				if c.ID != "output-ipsec-model" {
					continue
				}
				if c.Status != tc.status {
					t.Fatalf("got %s, want %s (%s)", c.Status, tc.status, c.Detail)
				}
				if tc.detail != "" && !strings.Contains(c.Detail, tc.detail) {
					t.Fatalf("detail %q should mention %q", c.Detail, tc.detail)
				}
				return
			}
			t.Fatal("missing output-ipsec-model check")
		})
	}
}

// runCheck converts a standalone OPNsense config through Run and returns the
// named check. body goes inside <OPNsense>; anything in outside is a sibling of
// it, for legacy sections such as <openvpn>.
func runCheck(t *testing.T, id, body string, outside ...string) Check {
	t.Helper()
	raw := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>edge</hostname>
    <user><name>root</name><uid>0</uid></user>
  </system>
  <interfaces>
    <lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  ` + strings.Join(outside, "") + `
  <OPNsense>` + body + `</OPNsense>
</opnsense>`
	parsed, err := xmlutil.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	root := map[string]any{"opnsense": parsed["opnsense"]}
	report := Run(Context{
		FileName:    "check.xml",
		RawText:     raw,
		ParsedInput: parsed,
		MappedRoot:  root,
		OutputXML:   xmlutil.Write(root, true),
	})
	for _, c := range report.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("missing %s check", id)
	return Check{}
}

func TestCheckOpenVPNModel(t *testing.T) {
	instance := func(body string) string {
		return `<OpenVPN><Instances><Instance uuid="i1"><role>server</role><proto>udp</proto>
      <topology>subnet</topology><description>road warriors</description>
      <keepalive_interval>10</keepalive_interval><keepalive_timeout>60</keepalive_timeout>` + body + `</Instance></Instances></OpenVPN>`
	}
	// Instances with no keepalive at all, which is what OpenVPN logs about.
	bare := func(body string) string {
		return `<OpenVPN><Instances><Instance uuid="i1"><role>server</role><proto>udp</proto>
      <topology>subnet</topology><description>road warriors</description>` + body + `</Instance></Instances></OpenVPN>`
	}
	cases := []struct {
		name, body, outside, status, detail string
	}{
		{
			name:   "valid",
			body:   instance(`<vpnid>1</vpnid><server>10.8.0.0/24</server><data-ciphers>AES-256-GCM</data-ciphers>`),
			status: "pass",
		},
		{
			name: "duplicate vpnid across server and client",
			body: `<OpenVPN><Instances>
        <Instance uuid="i1"><role>server</role><proto>udp</proto><topology>subnet</topology><vpnid>1</vpnid><description>road warriors</description></Instance>
        <Instance uuid="i2"><role>client</role><proto>udp</proto><topology>subnet</topology><vpnid>1</vpnid><description>upstream</description></Instance>
      </Instances></OpenVPN>`,
			status: "fail",
			detail: `both open /dev/tun1 and the second one fails with "Device busy"`,
		},
		{
			name:    "MVC instance collides with a surviving legacy server",
			body:    instance(`<vpnid>1</vpnid>`),
			outside: `<openvpn><openvpn-server><vpnid>1</vpnid><description>old server</description></openvpn-server></openvpn>`,
			status:  "fail",
			detail:  "legacy server",
		},
		{
			name:   "remote is not a host:port pair",
			body:   instance(`<vpnid>1</vpnid><remote>vpn.example.net 1195</remote>`),
			status: "fail",
			detail: "is not a host:port pair",
		},
		{
			name:   "tunnel network carries host bits",
			body:   instance(`<vpnid>1</vpnid><server>10.8.0.1/24</server>`),
			status: "warn",
			detail: "host bits",
		},
		{
			name:   "cipher outside the OPNsense list",
			body:   instance(`<vpnid>1</vpnid><data-ciphers>CAMELLIA-256-CBC</data-ciphers>`),
			status: "warn",
			detail: "CAMELLIA-256-CBC",
		},
		{
			name:   "no keepalive at all",
			body:   bare(`<vpnid>1</vpnid>`),
			status: "warn",
			detail: "--keepalive option is missing",
		},
		{
			name:   "only one half of the keepalive pair",
			body:   bare(`<vpnid>1</vpnid><keepalive_interval>10</keepalive_interval>`),
			status: "fail",
			detail: "both or neither",
		},
		{
			name:   "timeout below twice the interval",
			body:   bare(`<vpnid>1</vpnid><keepalive_interval>10</keepalive_interval><keepalive_timeout>15</keepalive_timeout>`),
			status: "fail",
			detail: "below twice the interval",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := runCheck(t, "output-openvpn-model", tc.body, tc.outside)
			if c.Status != tc.status {
				t.Fatalf("got %s, want %s (%s)", c.Status, tc.status, c.Detail)
			}
			if tc.detail != "" && !strings.Contains(c.Detail, tc.detail) {
				t.Fatalf("detail %q should mention %q", c.Detail, tc.detail)
			}
		})
	}
}

func TestCheckWireGuard(t *testing.T) {
	wg := func(servers, clients string) string {
		return `<wireguard><general version="0.0.1"><enabled>1</enabled></general>
      <server version="1.0.1"><servers>` + servers + `</servers></server>
      <client version="1.0.0"><clients>` + clients + `</clients></client></wireguard>`
	}
	peer := `<client uuid="p1"><enabled>1</enabled><name>laptop</name>
      <pubkey>eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6aB8cD0eF2e=</pubkey>
      <tunneladdress>10.6.0.2/32</tunneladdress></client>`
	instance := func(body string) string {
		return `<server uuid="s1"><enabled>1</enabled><name>Road_Warrior</name>
      <privkey>cP1hE1w0Xk8m2N4vQ6rT8yU0iO2pA4sD6fG8hJ0kL2w=</privkey>
      <tunneladdress>10.6.0.1/24</tunneladdress>` + body + `</server>`
	}
	cases := []struct {
		name, body, status, detail string
	}{
		{
			name:   "valid",
			body:   wg(instance(`<instance>0</instance><peers>p1</peers>`), peer),
			status: "pass",
		},
		{
			name:   "instance references a peer that was not written",
			body:   wg(instance(`<instance>0</instance><peers>ghost</peers>`), peer),
			status: "fail",
			detail: "not in the output",
		},
		{
			name: "two tunnels claim the same wg device",
			body: wg(instance(`<instance>0</instance>`)+
				`<server uuid="s2"><name>Site_B</name><instance>0</instance>
        <privkey>dQ2iF2x1Yl9n3O5wR7sU9zV1jP3qB5tE7gH9iK1lM3x=</privkey>
        <tunneladdress>10.7.0.1/30</tunneladdress></server>`, peer),
			status: "fail",
			detail: "claim wg0",
		},
		{
			name:   "peer without a public key",
			body:   wg(instance(`<instance>0</instance>`), `<client uuid="p1"><name>laptop</name><tunneladdress>10.6.0.2/32</tunneladdress></client>`),
			status: "fail",
			detail: "no public key",
		},
		{
			name:   "name outside the model mask",
			body:   wg(instance(`<instance>0</instance>`), `<client uuid="p1"><name>laptop (jane)</name><pubkey>k=</pubkey><tunneladdress>10.6.0.2/32</tunneladdress></client>`),
			status: "fail",
			detail: "alphanumeric",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := runCheck(t, "output-wireguard", tc.body)
			if c.Status != tc.status {
				t.Fatalf("got %s, want %s (%s)", c.Status, tc.status, c.Detail)
			}
			if tc.detail != "" && !strings.Contains(c.Detail, tc.detail) {
				t.Fatalf("detail %q should mention %q", c.Detail, tc.detail)
			}
		})
	}
}

func TestCheckIPsecFailsNestedOnOpnInput(t *testing.T) {
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
      </Swanctl>
    </IPsec>
  </OPNsense>
</opnsense>`
	parsed, err := xmlutil.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	root := map[string]any{"opnsense": parsed["opnsense"]}
	report := Run(Context{
		FileName:    "nested.xml",
		RawText:     raw,
		ParsedInput: parsed,
		MappedRoot:  root,
		OutputXML:   xmlutil.Write(root, true),
	})
	for _, c := range report.Checks {
		if c.ID != "output-ipsec" {
			continue
		}
		if c.Status != "fail" {
			t.Fatalf("nested Swanctl on OPNsense input must fail, got %s (%s)", c.Status, c.Detail)
		}
		if !strings.Contains(c.Detail, "IPsec/Swanctl") {
			t.Fatalf("failure should name the nested mount: %s", c.Detail)
		}
		return
	}
	t.Fatal("missing output-ipsec check")
}
