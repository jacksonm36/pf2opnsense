package mapper

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

var nicePrefix = regexp.MustCompile(`(?i)^(?:/usr/bin/nice\s+-n\s*-?\d+\s+|nice\s+-n\s*-?\d+\s+|nice\s+-?\d+\s+)+`)

func mapCron(pfsense map[string]any, opt *Options, report *Notes) map[string]any {
	items := xmlutil.AsArray(xmlutil.Get(pfsense, "cron", "item"))
	jobs := []any{}
	omitted := []string{}
	for _, raw := range items {
		item := xmlutil.Map(raw)
		cmd := strings.TrimSpace(xmlutil.AsString(item["command"]))
		if cmd == "" {
			omitted = append(omitted, "empty command")
			continue
		}
		who := orDefault(xmlutil.AsString(item["who"]), "root")
		action, params, dropReason := ClassifyCron(cmd)
		if dropReason != "" {
			omitted = append(omitted, dropReason)
			continue
		}
		if action == "" {
			omitted = append(omitted, "unsupported command: "+stripNice(cmd))
			continue
		}
		jobs = append(jobs, map[string]any{
			"@_uuid":      nextUUID(opt),
			"origin":      "cron",
			"enabled":     "1",
			"minutes":     cronField(item["minute"]),
			"hours":       cronField(item["hour"]),
			"days":        cronField(item["mday"]),
			"months":      cronField(item["month"]),
			"weekdays":    cronField(item["wday"]),
			"who":         who,
			"command":     action,
			"parameters":  params,
			"description": "Mapped from pfSense: " + stripNice(cmd),
		})
	}
	if len(omitted) > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"Omitted %d pfSense cron job(s) that OPNsense already handles or cannot run (%s).",
			len(omitted), summarizeCronOmits(omitted)))
	}
	if len(jobs) == 0 {
		return nil
	}
	report.Notes = append(report.Notes, fmt.Sprintf(
		"Mapped %d cron job(s) to System → Settings → Cron (OPNsense configd actions).", len(jobs)))
	return map[string]any{"jobs": map[string]any{"job": jobs}}
}

func cronField(value any) string {
	s := strings.TrimSpace(xmlutil.AsString(value))
	if s == "" {
		return "*"
	}
	return s
}

func stripNice(cmd string) string {
	return strings.TrimSpace(nicePrefix.ReplaceAllString(cmd, ""))
}

// ClassifyCron returns an OPNsense configd action, optional parameters, and a
// drop reason. pfSense jobs that are not configctl actions cannot run on
// OPNsense cron (which only executes configd actions).
func ClassifyCron(cmd string) (action, params, dropReason string) {
	c := stripNice(cmd)
	lower := strings.ToLower(c)
	switch {
	case strings.Contains(lower, "rc.update_bogons") || strings.Contains(lower, "update_bogons"):
		return "", "", "bogons (OPNsense schedules this from System settings)"
	case strings.Contains(lower, "rc.dyndns") || strings.Contains(lower, "dyndns.update"):
		return "", "", "DynDNS (handled by os-ddclient)"
	case strings.Contains(lower, "update_urltables"):
		return "", "", "URL tables (OPNsense refreshes aliases automatically)"
	case strings.Contains(lower, "/usr/local/pkg/"):
		return "", "", "pfSense package script"
	case strings.Contains(lower, "adjkerntz"):
		return "", "", "adjkerntz (NTP handles timezone)"
	case strings.Contains(lower, "expiretable"):
		return "", "", "expiretable (OPNsense expires firewall tables itself)"
	}
	idx := strings.Index(lower, "configctl ")
	if idx < 0 {
		return "", "", ""
	}
	rest := strings.TrimSpace(c[idx+len("configctl "):])
	if cut := strings.IndexAny(rest, "><"); cut >= 0 {
		rest = strings.TrimSpace(rest[:cut])
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", "", ""
	}
	if len(fields) == 1 {
		return fields[0], "", ""
	}
	return fields[0] + " " + fields[1], strings.Join(fields[2:], " "), ""
}

func summarizeCronOmits(reasons []string) string {
	counts := map[string]int{}
	order := []string{}
	for _, r := range reasons {
		label := r
		if i := strings.Index(r, " ("); i > 0 {
			label = r[:i]
		}
		if strings.HasPrefix(r, "unsupported command:") {
			label = "custom/unsupported commands"
		}
		if counts[label] == 0 {
			order = append(order, label)
		}
		counts[label]++
	}
	parts := []string{}
	for _, label := range order {
		parts = append(parts, fmt.Sprintf("%s×%d", label, counts[label]))
	}
	return strings.Join(parts, ", ")
}
