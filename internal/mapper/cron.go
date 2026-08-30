package mapper

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

var nicePrefix = regexp.MustCompile(`(?i)^(?:/usr/bin/nice\s+-n\s*\d+\s+)+`)

func mapCron(pfsense map[string]any, opt *Options, report *Notes) map[string]any {
	items := xmlutil.AsArray(xmlutil.Get(pfsense, "cron", "item"))
	jobs := []any{}
	omitted := []string{}
	for _, raw := range items {
		item := xmlutil.Map(raw)
		cmd := strings.TrimSpace(xmlutil.AsString(item["command"]))
		if cmd == "" {
			continue
		}
		who := orDefault(xmlutil.AsString(item["who"]), "root")
		action, dropReason := ClassifyCron(cmd)
		if dropReason != "" {
			omitted = append(omitted, dropReason)
			continue
		}
		if action == "" {
			omitted = append(omitted, "unsupported command: "+stripNice(cmd))
			continue
		}
		jobs = append(jobs, map[string]any{
			"@_uuid":     nextUUID(opt),
			"origin":     "cron",
			"enabled":    "1",
			"minutes":    orDefault(xmlutil.AsString(item["minute"]), "0"),
			"hours":      orDefault(xmlutil.AsString(item["hour"]), "0"),
			"days":       orDefault(xmlutil.AsString(item["mday"]), "*"),
			"months":     orDefault(xmlutil.AsString(item["month"]), "*"),
			"weekdays":   orDefault(xmlutil.AsString(item["wday"]), "*"),
			"who":        who,
			"command":    action,
			"parameters": "",
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

func stripNice(cmd string) string {
	return strings.TrimSpace(nicePrefix.ReplaceAllString(cmd, ""))
}

func ClassifyCron(cmd string) (action, dropReason string) {
	c := stripNice(cmd)
	lower := strings.ToLower(c)
	switch {
	case strings.Contains(lower, "rc.update_bogons") || strings.Contains(lower, "update_bogons"):
		return "", "bogons (OPNsense schedules this from System settings)"
	case strings.Contains(lower, "rc.dyndns") || strings.Contains(lower, "dyndns.update"):
		return "", "DynDNS (handled by os-ddclient)"
	case strings.Contains(lower, "update_urltables"):
		return "", "URL tables (OPNsense refreshes aliases automatically)"
	case strings.Contains(lower, "/usr/local/pkg/"):
		return "", "pfSense package script"
	case strings.Contains(lower, "adjkerntz"):
		return "", "adjkerntz (NTP handles timezone)"
	case strings.Contains(lower, "expiretable"):
		return "", "expiretable (OPNsense expires firewall tables itself)"
	}
	if strings.Contains(lower, "configctl ") {
		idx := strings.Index(lower, "configctl ")
		rest := strings.TrimSpace(c[idx+len("configctl "):])
		if rest != "" {
			return rest, ""
		}
	}
	return "", ""
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
