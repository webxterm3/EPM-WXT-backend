package api

import (
	"strings"
	"testing"
	"time"
)

// A bare date is what a human types into a filter. Rejecting it would mean the
// filter only works for people who know the RFC.
func TestParseTimeQueryAcceptsWhatPeopleType(t *testing.T) {
	cases := map[string]time.Time{
		"2026-10-07":                time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC),
		"2026-10-07T14:30:00":       time.Date(2026, 10, 7, 14, 30, 0, 0, time.UTC),
		"2026-10-07T14:30:00Z":      time.Date(2026, 10, 7, 14, 30, 0, 0, time.UTC),
		"2026-10-07T20:00:00+05:30": time.Date(2026, 10, 7, 14, 30, 0, 0, time.UTC),
	}
	for in, want := range cases {
		got := parseTimeQuery(in)
		if !got.Equal(want) {
			t.Errorf("parseTimeQuery(%q) = %s, want %s", in, got, want)
		}
	}

	// Anything unreadable becomes "no filter" rather than a date nobody meant.
	for _, in := range []string{"", "   ", "last tuesday", "07/10/2026"} {
		if got := parseTimeQuery(in); !got.IsZero() {
			t.Errorf("parseTimeQuery(%q) = %s, want no filter", in, got)
		}
	}
}

// Two exports of the same data must be byte-identical, or they cannot be
// diffed and a spreadsheet's columns shift between downloads.
func TestDetailsEncodingIsStable(t *testing.T) {
	details := map[string]any{
		"policy": "business-hours", "access_kind": "attended",
		"reason": "outside hours", "machine": "laptop-7",
	}

	first := encodeDetails(details)
	for i := 0; i < 20; i++ {
		if got := encodeDetails(details); got != first {
			t.Fatalf("encoding changed between calls:\n%q\n%q", first, got)
		}
	}
	if !strings.HasPrefix(first, "access_kind=") {
		t.Errorf("details are not sorted: %q", first)
	}
	if encodeDetails(nil) != "" {
		t.Error("empty details did not encode to an empty cell")
	}
}

// The filter menu has to offer every event the product claims to record, not
// only those that happen to exist in one tenant's data today.
func TestKnownActionsCoverTheWholeTaxonomy(t *testing.T) {
	actions := knownActions()
	if len(actions) < 15 {
		t.Fatalf("only %d actions declared", len(actions))
	}

	seen := map[string]bool{}
	for _, a := range actions {
		if seen[a] {
			t.Errorf("%q is listed twice", a)
		}
		seen[a] = true
		if !strings.Contains(a, ".") {
			t.Errorf("%q does not follow the resource.verb shape", a)
		}
	}

	// The events that only exist once enforcement does must still be declared,
	// so the UI can show them as "not recorded yet" rather than omitting them.
	for _, want := range []string{
		"application.blocked", "application.elevated",
		"sudo.executed", "jit.approved",
	} {
		if !seen[want] {
			t.Errorf("%q is missing from the taxonomy", want)
		}
	}
}

// An empty "applications blocked: 0" is indistinguishable from "nothing was
// blocked" unless the report says the control does not exist — and that
// difference is the whole value of the document.
func TestReportNamesWhatIsNotRecorded(t *testing.T) {
	gaps := notYetRecorded(true)
	if len(gaps) == 0 {
		t.Fatal("the report claims to record everything")
	}

	// With enforcement off the report must say so outright, or its zero
	// enforcement counts read as "nothing matched" rather than "nothing was
	// ever going to be blocked".
	off := strings.ToLower(strings.Join(notYetRecorded(false), " "))
	if !strings.Contains(off, "audit mode") {
		t.Error("with enforcement off, the report does not say the counts are zero by design")
	}
	if len(notYetRecorded(false)) <= len(gaps) {
		t.Error("turning enforcement off did not add a caveat to the report")
	}

	joined := strings.ToLower(strings.Join(gaps, " "))
	for _, subject := range []string{"application", "sudo", "administrator", "just-in-time"} {
		if !strings.Contains(joined, subject) {
			t.Errorf("the gaps do not mention %q", subject)
		}
	}
	// And it must be explicit that the portal's own sign-in log lives
	// elsewhere, or a reader assumes this document is the whole trail.
	if !strings.Contains(joined, "authentication service") {
		t.Error("the report does not say that portal sign-ins are recorded separately")
	}
}

func TestPaginationCeiling(t *testing.T) {
	// A caller asking for a million rows gets the default, not a million.
	for _, raw := range []string{"1000000", "-5", "0", "abc"} {
		limit, _ := paginationFrom(raw, "0", 50, 500)
		if limit != 50 {
			t.Errorf("limit for %q = %d, want the default 50", raw, limit)
		}
	}
	if limit, _ := paginationFrom("200", "0", 50, 500); limit != 200 {
		t.Errorf("a reasonable limit was not honoured: %d", limit)
	}
	if _, skip := paginationFrom("50", "-10", 50, 500); skip != 0 {
		t.Errorf("negative skip = %d, want 0", skip)
	}
}
