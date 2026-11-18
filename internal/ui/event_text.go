package ui

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/avazar/zaslon/internal/guard"
)

func endpointLabel(endpoint, family string, full bool) string {
	if !full {
		if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
			endpoint = u.Host
		}
	}
	return strings.TrimSpace(endpoint + " " + family)
}

func problemText(p guard.CheckProblem, full bool) string {
	label := endpointLabel(p.Endpoint, p.Family, full)
	var body string
	switch p.Code {
	case "http", "country", "denied":
		body = T("hist."+p.Code, p.Info)
	default:
		code := p.Code
		if code == "error" && strings.HasPrefix(p.Info, "lookup ") {
			code = "dns"
		}
		body = T("hist." + code)
		if full && p.Info != "" {
			body += " (" + p.Info + ")"
		}
	}
	if label == "" {
		return body
	}
	return label + " — " + body
}

func eventMessage(e guard.Event, full bool) string {
	var parts []string
	title := eventTitle(e)
	switch e.Kind {
	case guard.EvFrozen, guard.EvHoldReason:
		if len(e.HeldBy) > 0 && e.Reason == guard.ProcessPolicyDenied {
			parts = append(parts, T("hist.by", appsText(e.HeldBy)))
		} else {
			explained := false
			for _, p := range e.Problems {
				switch e.Reason {
				case guard.DomainIPNotAllowed:
					explained = p.Code == "denied"
				case guard.CountryUnknown, guard.IPv6CountryUnknown:
					explained = p.Code == "country"
				case guard.DomainUnconfirmed, guard.IPv6Unconfirmed:
					explained = p.Code != "denied" && p.Code != "country" && (p.Family == "" || (e.Reason == guard.IPv6Unconfirmed) == (p.Family == "IPv6"))
				}
				if explained {
					break
				}
			}
			if !explained {
				reason := reasonText(e.Reason)
				if e.Reason == guard.IPNotAllowed && e.IP != "" {
					reason = T("hist.denied", IPWithCountry(e.IP, e.Country))
				}
				parts = append(parts, reason)
			}
		}
	case guard.EvProcessError:
		if full {
			parts = append(parts, e.Error)
		}
	case guard.EvResumed:
		if e.ReleaseCause != "" {
			parts = append(parts, T("hist."+e.ReleaseCause))
		} else if !e.IgnoredChecks {
			parts = append(parts, T("hist.verified"))
		}
		if e.PauseMax > 0 {
			short, long := Dur(e.PauseMin), Dur(e.PauseMax)
			if short == long {
				parts = append(parts, T("hist.duration", long))
			} else {
				parts = append(parts, T("hist.range", short, long))
			}
		}
	}
	if e.RetryFamily != "" {
		parts = append(parts, endpointLabel(e.Domain, e.RetryFamily, full)+" — "+T("hist.retry_timeout"))
	}
	for _, p := range e.Problems {
		parts = append(parts, problemText(p, full))
	}
	if e.Repeats > 0 {
		parts = append(parts, T("hist.again", e.Repeats))
	}
	return strings.Join(append([]string{title}, parts...), " · ")
}

func checkRef(e guard.Event) string {
	if e.Repeats > 0 {
		return fmt.Sprintf("check=%d..%d", e.FirstCheck, e.CheckID)
	}
	return fmt.Sprintf("check=%d", e.CheckID)
}

func eventDetails(e guard.Event) []string {
	var details []string
	if e.CheckID != 0 {
		details = append(details, checkRef(e))
	}
	for _, p := range e.Problems {
		details = append(details, problemText(p, true))
	}
	if e.RetryFamily != "" {
		details = append(details, endpointLabel(e.Domain, e.RetryFamily, true))
	}
	if e.Kind == guard.EvProcessError {
		details = append(details, e.Error)
	}
	return append(details, e.Details...)
}

func logMessage(e guard.Event) string {
	message := eventMessage(e, true)
	if e.Repeats > 0 {
		message = T("hist.repeated", appsText(e.Apps)) + " · " + T("hist.again", e.Repeats)
	}
	if e.CheckID != 0 {
		message += " | " + checkRef(e)
	}
	for _, detail := range e.Details {
		message += " | " + guard.DiagnosticText(detail)
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\u2028', '\u2029':
			return ' '
		}
		return r
	}, message)
}

// EventLine is the complete single-line rendering for diagnostics.
func EventLine(e guard.Event) string {
	return e.At.Local().Format("15:04:05") + "  " + logMessage(e)
}
