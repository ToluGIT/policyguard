package html

import (
	"encoding/json"
	"html/template"
	"strings"
)

// findingsToJSON serializes the findings into a JSON string safe to embed in a
// <script type="application/json"> island read via JSON.parse(textContent).
// encoding/json (SetEscapeHTML true, the default) escapes <, >, & to < etc.
// — which prevents a </script> breakout — and also escapes U+2028/U+2029 to
//  / , so no manual post-processing is needed. The browser does not
// decode HTML entities inside an application/json block, so we must not
// entity-encode here either.
func findingsToJSON(findings []Finding) string {
	// A trimmed client-side shape — only what the JS needs for filter/search/
	// select. Full detail is rendered server-side into the DOM; the JS shows/
	// hides by index, so this island stays small.
	type clientFinding struct {
		Index    int    `json:"i"`
		Resource string `json:"r"`
		Type     string `json:"t"`
		Policy   string `json:"p"`
		Title    string `json:"m"`
		Severity string `json:"s"`
		File     string `json:"f"`
		Line     int    `json:"l"`
	}
	out := make([]clientFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, clientFinding{
			Index: f.Index, Resource: f.ResourceID, Type: f.ResourceType,
			Policy: f.PolicyID, Title: f.Title, Severity: f.Severity,
			File: f.File, Line: f.Line,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// templateFuncs are the helpers available inside the dashboard template.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		// fileLine renders "file:line", or just the file when line<=0, or "" when
		// no file. Used in the table and detail header.
		"fileLine": func(file string, line int) string {
			if file == "" {
				return ""
			}
			if line <= 0 {
				return file
			}
			return file + ":" + itoa(line)
		},
		// pct formats a percentage for inline style widths.
		"pct": func(v float64) template.CSS {
			return template.CSS(ftoa(v) + "%")
		},
		// hasItems reports whether a string slice is non-empty (for conditionally
		// rendering CIS/NIST rows only when populated).
		"hasItems": func(s []string) bool { return len(s) > 0 },
		"join":     strings.Join,
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func ftoa(v float64) string {
	// One decimal place, no exponent — enough for width percentages.
	if v < 0 {
		v = 0
	}
	scaled := int(v*10 + 0.5)
	whole := scaled / 10
	frac := scaled % 10
	return itoa(whole) + "." + itoa(frac)
}
