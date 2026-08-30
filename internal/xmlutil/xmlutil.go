package xmlutil

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ArrayTags = map[string]struct{}{
	"alias": {}, "rule": {}, "user": {}, "group": {}, "dnsserver": {},
	"winsserver": {}, "radnsserver": {}, "ntpserver": {}, "gateway_item": {},
	"gateway_group": {}, "staticmap": {}, "vlan": {}, "lagg": {}, "bridged": {},
	"cert": {}, "ca": {}, "crl": {}, "priv": {}, "member": {}, "item": {},
	"hosts": {}, "dhcp_ranges": {}, "openvpn-server": {}, "openvpn-client": {},
	"openvpn-csc": {}, "onetoone": {}, "vip": {}, "phase1": {}, "phase2": {},
	"route": {}, "package": {}, "account": {}, "dyndns": {}, "ppp": {},
	"mobilekey": {}, "Instance": {}, "Overwrite": {}, "StaticKey": {},
	"Connection": {}, "child": {}, "local": {}, "remote": {},
	"preSharedKey": {}, "job": {}, "SPD": {}, "subnet4": {}, "reservation": {},
}

func Parse(raw []byte) (map[string]any, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Entity = xml.HTMLEntity
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			val, err := parseElement(dec, t)
			if err != nil {
				return nil, err
			}
			root := map[string]any{t.Name.Local: val}
			ForceArrays(root)
			return root, nil
		case xml.CharData, xml.Comment, xml.ProcInst, xml.Directive:
			continue
		}
	}
}

func parseElement(dec *xml.Decoder, start xml.StartElement) (any, error) {
	children := map[string]any{}
	var text strings.Builder
	hasChild := false

	for _, attr := range start.Attr {
		if attr.Name.Space == "xmlns" || attr.Name.Local == "xmlns" {
			continue
		}
		children["@_"+attr.Name.Local] = attr.Value
	}

	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			hasChild = true
			child, err := parseElement(dec, t)
			if err != nil {
				return nil, err
			}
			name := t.Name.Local
			if existing, ok := children[name]; ok {
				if arr, ok := existing.([]any); ok {
					children[name] = append(arr, child)
				} else {
					children[name] = []any{existing, child}
				}
			} else {
				children[name] = child
			}
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			trimmed := html.UnescapeString(strings.TrimSpace(text.String()))
			if !hasChild && len(children) == 0 {
				return trimmed, nil
			}
			if !hasChild && len(children) > 0 && trimmed == "" {
				return children, nil
			}
			if trimmed != "" && !hasChild {
				if len(children) == 0 {
					return trimmed, nil
				}
				children["#text"] = trimmed
			}
			return children, nil
		case xml.Comment, xml.ProcInst, xml.Directive:
			continue
		}
	}
}

func ForceArrays(v any) {
	switch n := v.(type) {
	case map[string]any:
		for key, child := range n {
			if _, want := ArrayTags[key]; want {
				n[key] = AsArray(child)
			}
			ForceArrays(child)
		}
	case []any:
		for _, child := range n {
			ForceArrays(child)
		}
	}
}

func Write(root map[string]any, pretty bool) string {
	var buf strings.Builder
	buf.WriteString(`<?xml version="1.0"?>`)
	if pretty {
		buf.WriteByte('\n')
	}
	keys := Keys(root)
	for _, key := range keys {
		writeNode(&buf, key, root[key], 0, pretty)
	}
	return buf.String()
}

func writeNode(buf *strings.Builder, name string, value any, depth int, pretty bool) {
	if strings.HasPrefix(name, "@_") || name == "#text" {
		return
	}
	indent := ""
	if pretty {
		indent = strings.Repeat("  ", depth)
	}
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			writeNode(buf, name, item, depth, pretty)
		}
	case map[string]any:
		attrs, children, text := splitMap(v)
		if pretty {
			buf.WriteString(indent)
		}
		buf.WriteByte('<')
		buf.WriteString(name)
		for _, a := range attrs {
			buf.WriteByte(' ')
			buf.WriteString(strings.TrimPrefix(a.key, "@_"))
			buf.WriteString(`="`)
			buf.WriteString(xmlEscapeAttr(a.val))
			buf.WriteByte('"')
		}
		if len(children) == 0 && text == "" {
			buf.WriteString("></")
			buf.WriteString(name)
			buf.WriteByte('>')
			if pretty {
				buf.WriteByte('\n')
			}
			return
		}
		buf.WriteByte('>')
		if len(children) == 0 {
			buf.WriteString(xmlEscapeText(text))
			buf.WriteString("</")
			buf.WriteString(name)
			buf.WriteByte('>')
			if pretty {
				buf.WriteByte('\n')
			}
			return
		}
		if pretty {
			buf.WriteByte('\n')
		}
		if text != "" {
			if pretty {
				buf.WriteString(strings.Repeat("  ", depth+1))
			}
			buf.WriteString(xmlEscapeText(text))
			if pretty {
				buf.WriteByte('\n')
			}
		}
		for _, child := range children {
			writeNode(buf, child.key, child.val, depth+1, pretty)
		}
		if pretty {
			buf.WriteString(indent)
		}
		buf.WriteString("</")
		buf.WriteString(name)
		buf.WriteByte('>')
		if pretty {
			buf.WriteByte('\n')
		}
	case nil:
		if pretty {
			buf.WriteString(indent)
		}
		buf.WriteByte('<')
		buf.WriteString(name)
		buf.WriteString("></")
		buf.WriteString(name)
		buf.WriteByte('>')
		if pretty {
			buf.WriteByte('\n')
		}
	default:
		if pretty {
			buf.WriteString(indent)
		}
		s := fmt.Sprint(v)
		buf.WriteByte('<')
		buf.WriteString(name)
		buf.WriteByte('>')
		buf.WriteString(xmlEscapeText(s))
		buf.WriteString("</")
		buf.WriteString(name)
		buf.WriteByte('>')
		if pretty {
			buf.WriteByte('\n')
		}
	}
}

type kv struct {
	key string
	val any
}

func splitMap(m map[string]any) (attrs []kv, children []kv, text string) {
	keys := Keys(m)
	for _, key := range keys {
		if key == "#text" {
			text = AsString(m[key])
			continue
		}
		if strings.HasPrefix(key, "@_") {
			attrs = append(attrs, kv{key: key, val: m[key]})
			continue
		}
		children = append(children, kv{key: key, val: m[key]})
	}
	return
}

func Keys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	preferred := []string{
		"theme", "system", "interfaces", "vlans", "nat", "filter", "unbound",
		"rrd", "ntpd", "revision", "dnsmasq", "installedpackages", "OPNsense",
		"ca", "cert", "crl", "ipsec", "staticroutes", "virtualip", "bridges",
		"laggs", "gifs", "gres", "ppps", "wol", "syslog", "cron", "gateways",
		"captiveportal", "shaper", "dnshaper", "load_balancer", "ifgroups",
		"qinqs", "wireless", "wireguard",
	}
	seen := map[string]struct{}{}
	ordered := make([]string, 0, len(m))
	for _, key := range preferred {
		if _, ok := m[key]; ok {
			ordered = append(ordered, key)
			seen[key] = struct{}{}
		}
	}
	rest := make([]string, 0)
	for _, key := range keys {
		if _, ok := seen[key]; !ok {
			rest = append(rest, key)
		}
	}
	sort.Strings(rest)
	return append(ordered, rest...)
}

func xmlEscapeText(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func xmlEscapeAttr(v any) string {
	s := AsString(v)
	s = strings.ReplaceAll(s, `&`, "&amp;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, `<`, "&lt;")
	return s
}

func AsArray(value any) []any {
	if value == nil {
		return nil
	}
	if s, ok := value.(string); ok && s == "" {
		return nil
	}
	if arr, ok := value.([]any); ok {
		return arr
	}
	return []any{value}
}

func AsString(value any) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case map[string]any:
		if t, ok := v["#text"]; ok {
			return fmt.Sprint(t)
		}
		if t, ok := v["CDATA"]; ok {
			return fmt.Sprint(t)
		}
		if len(v) == 0 {
			return ""
		}
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func FlagSet(value any) bool {
	if value == nil {
		return false
	}
	if b, ok := value.(bool); ok {
		return b
	}
	s := AsString(value)
	if s == "0" {
		return false
	}
	return true
}

func Present01(value any) string {
	if FlagSet(value) {
		return "1"
	}
	return "0"
}

func YesFlag(value any) bool {
	raw := strings.ToLower(strings.TrimSpace(AsString(value)))
	return raw == "yes" || raw == "on" || raw == "1" || raw == "true"
}

func ClampInt(value any, min, max, fallback int) int {
	parsed, err := strconv.Atoi(AsString(value))
	if err != nil {
		return fallback
	}
	if parsed < min {
		return min
	}
	if parsed > max {
		return max
	}
	return parsed
}

func LowerIdent(value any) string {
	return strings.ToLower(strings.TrimSpace(AsString(value)))
}

func SplitList(value any) []string {
	raw := strings.TrimSpace(AsString(value))
	if raw == "" {
		return nil
	}
	parts := regexp.MustCompile(`[\s,]+`).Split(raw, -1)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func IsEmptySection(value any) bool {
	if value == nil {
		return true
	}
	if s, ok := value.(string); ok {
		return s == ""
	}
	if arr, ok := value.([]any); ok {
		return len(arr) == 0
	}
	if m, ok := value.(map[string]any); ok {
		return len(m) == 0
	}
	return false
}

func Map(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return nil
}

func Get(value any, path ...string) any {
	cur := value
	for _, key := range path {
		m := Map(cur)
		if m == nil {
			return nil
		}
		cur = m[key]
	}
	return cur
}

func CompactXML(xmlText string) string {
	re := regexp.MustCompile(`>\s+<`)
	return re.ReplaceAllString(xmlText, "><")
}

func WellFormed(raw string) error {
	dec := xml.NewDecoder(strings.NewReader(raw))
	foundRoot := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if !foundRoot {
				return fmt.Errorf("no XML root element")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if _, ok := tok.(xml.StartElement); ok {
			foundRoot = true
		}
	}
}
