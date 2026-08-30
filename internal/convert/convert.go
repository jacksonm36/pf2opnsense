package convert

import (
	"strings"

	"github.com/jacksonm36/pf2opnsense/internal/mapper"
	"github.com/jacksonm36/pf2opnsense/internal/validate"
	"github.com/jacksonm36/pf2opnsense/internal/xmlutil"
)

type Result struct {
	XML        string          `json:"xml"`
	CompactXML string          `json:"compactXml"`
	Notes      []string        `json:"notes"`
	Skipped    []string        `json:"skipped"`
	Stats      mapper.Stats    `json:"stats"`
	Validation validate.Report `json:"validation"`
}

func Run(fileName, rawText string, opt ...*mapper.Options) Result {
	ctx := validate.Context{FileName: fileName, RawText: rawText}
	trimmed := strings.TrimSpace(rawText)
	if trimmed == "" {
		return Result{Validation: validate.Run(ctx), Stats: mapper.Stats{}, Notes: []string{}, Skipped: []string{}}
	}
	parsed, err := xmlutil.Parse([]byte(trimmed))
	if err != nil {
		return Result{Validation: validate.Run(ctx), Notes: []string{}, Skipped: []string{err.Error()}}
	}
	ctx.ParsedInput = parsed
	if xmlutil.Map(parsed["pfsense"]) == nil && xmlutil.Map(parsed["opnsense"]) == nil {
		return Result{
			Validation: validate.Run(ctx),
			Notes:      []string{},
			Skipped:    []string{"Not a pfSense or OPNsense configuration backup."},
		}
	}
	var mapOpt *mapper.Options
	if len(opt) > 0 {
		mapOpt = opt[0]
	}
	mapped, err := mapper.Map(parsed, mapOpt)
	if err != nil {
		ctx.ConvertErr = err.Error()
		return Result{Validation: validate.Run(ctx), Notes: []string{}, Skipped: []string{err.Error()}}
	}
	if mapped == nil {
		ctx.ConvertErr = "mapper returned no result"
		return Result{Validation: validate.Run(ctx), Notes: []string{}, Skipped: []string{ctx.ConvertErr}}
	}
	pretty := toXML(mapped, true)
	compact := xmlutil.CompactXML(toXML(mapped, false))
	ctx.MappedRoot = mapped.Root
	ctx.OutputXML = pretty
	ctx.Report = &mapped.Report
	report := validate.Run(ctx)
	notes, skipped := mapped.Report.Notes, mapped.Report.Skipped
	if notes == nil {
		notes = []string{}
	}
	if skipped == nil {
		skipped = []string{}
	}
	out := Result{
		Notes:      notes,
		Skipped:    skipped,
		Stats:      mapped.Report.Stats,
		Validation: report,
	}
	if report.CanDownload {
		out.XML = pretty
		out.CompactXML = compact
	}
	return out
}

func toXML(mapped *mapper.Result, pretty bool) string {
	body := xmlutil.Write(mapped.Root, pretty)
	body = strings.TrimPrefix(body, `<?xml version="1.0"?>`)
	body = strings.TrimLeft(body, "\n")
	comment := strings.ReplaceAll(mapper.BuildComment(mapped.Report), "--", "—")
	return "<?xml version=\"1.0\"?>\n<!--\n" + comment + "\n-->\n" + body
}
