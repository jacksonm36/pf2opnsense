package validate

import (
	"strings"
	"testing"

	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

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
