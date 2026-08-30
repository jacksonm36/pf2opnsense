package xmlutil

import (
	"strings"
	"testing"
)

// ArrayTags is keyed on the bare tag name, so <local>/<remote> are forced into
// slices for the IPsec Swanctl lists even where OpenVPN uses them as scalars.
func TestAsStringReadsThroughForcedArrays(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<opnsense>
  <OPNsense>
    <OpenVPN>
      <Instances>
        <Instance uuid="a">
          <local>198.51.100.10</local>
          <remote>vpn.example.net:1195</remote>
        </Instance>
      </Instances>
    </OpenVPN>
  </OPNsense>
</opnsense>`)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	inst := Map(AsArray(Get(parsed, "opnsense", "OPNsense", "OpenVPN", "Instances", "Instance"))[0])
	for _, tc := range []struct{ field, want string }{
		{"local", "198.51.100.10"},
		{"remote", "vpn.example.net:1195"},
	} {
		if got := AsString(inst[tc.field]); got != tc.want {
			t.Errorf("AsString(%s) = %q, want %q", tc.field, got, tc.want)
		}
	}
	if got := AsString([]any{"a", "b"}); got != "" {
		t.Errorf("a real list has no single string value, got %q", got)
	}
}

func TestEmptyFlagAndAliasNewlines(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<pfsense>
  <enable/>
  <disabled></disabled>
  <off>0</off>
  <aliases>
    <alias>
      <name>hosts</name>
      <address>192.168.1.10 192.168.1.11</address>
    </alias>
  </aliases>
</pfsense>
`)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	pf := Map(parsed["pfsense"])
	if !FlagSet(pf["enable"]) {
		t.Fatal("empty <enable/> should be set")
	}
	if !FlagSet(pf["disabled"]) {
		t.Fatal("empty <disabled></disabled> should be set")
	}
	if FlagSet(pf["off"]) {
		t.Fatal(`<off>0</off> should not be set`)
	}
	if FlagSet(pf["missing"]) {
		t.Fatal("missing flag should not be set")
	}

	alias := Map(AsArray(Get(pf, "aliases", "alias"))[0])
	joined := strings.Join(SplitList(alias["address"]), "\n")
	out := map[string]any{
		"opnsense": map[string]any{
			"alias": map[string]any{"content": joined},
		},
	}
	xmlText := Write(out, true)
	if !strings.Contains(xmlText, "192.168.1.10\n192.168.1.11") {
		t.Fatalf("pretty XML must keep alias newlines:\n%s", xmlText)
	}
	compact := CompactXML(xmlText)
	if !strings.Contains(compact, "192.168.1.10\n192.168.1.11") {
		t.Fatalf("compact XML must not glue alias addresses:\n%s", compact)
	}
}

func TestHTMLEntitiesUnescape(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<pfsense>
  <user>
    <descr>Jos&amp;eacute; Garc&amp;iacute;a</descr>
  </user>
  <rule>
    <descr>Fran&ccedil;ois Dupr&eacute;</descr>
  </rule>
</pfsense>
`)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	pf := Map(parsed["pfsense"])
	user := Map(AsArray(Get(pf, "user"))[0])
	if AsString(user["descr"]) != "José García" {
		t.Fatalf("xml-escaped html entities: %q", AsString(user["descr"]))
	}
	rule := Map(AsArray(Get(pf, "rule"))[0])
	if AsString(rule["descr"]) != "François Dupré" {
		t.Fatalf("html named entities: %q", AsString(rule["descr"]))
	}
	xmlText := Write(parsed, true)
	if strings.Contains(xmlText, "&amp;eacute;") || strings.Contains(xmlText, "&ccedil;") {
		t.Fatalf("output still has html entities:\n%s", xmlText)
	}
	if !strings.Contains(xmlText, "José García") || !strings.Contains(xmlText, "François Dupré") {
		t.Fatalf("unicode names missing:\n%s", xmlText)
	}
}

func TestParseRejectsDeepNesting(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>`)
	const depth = maxDepth + 2
	for i := 0; i < depth; i++ {
		b.WriteString("<a>")
	}
	for i := 0; i < depth; i++ {
		b.WriteString("</a>")
	}
	if _, err := Parse([]byte(b.String())); err == nil {
		t.Fatal("expected nesting-depth error")
	} else if !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("got %v", err)
	}
}
