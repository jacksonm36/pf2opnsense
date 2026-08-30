package xmlutil

import (
	"strings"
	"testing"
)

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
