package email

import "testing"

// An approver reads this to decide. "%d hour(s)" turned a fifteen-minute
// request into "0 hour(s)", which reads as a request with no duration rather
// than the shortest one the product offers — and "no duration" used to mean
// permanent.
func TestADurationReadsAsWhatWasAskedFor(t *testing.T) {
	for _, c := range []struct {
		minutes int
		want    string
	}{
		{1, "1 minute(s)"},
		{15, "15 minute(s)"},
		{59, "59 minute(s)"},
		{60, "1 hour(s)"},
		{90, "1h 30m"},
		{24 * 60, "1 day(s)"},
		{36 * 60, "1d 12h"},
		{30 * 24 * 60, "30 day(s)"},
	} {
		if got := HumanDuration(c.minutes); got != c.want {
			t.Errorf("HumanDuration(%d) = %q, want %q", c.minutes, got, c.want)
		}
	}
}

// Zero is not a duration. It must not render as "0 minutes", which reads as a
// grant that is already over, nor be silently omitted.
func TestNoDurationSaysSo(t *testing.T) {
	for _, m := range []int{0, -1, -60} {
		got := HumanDuration(m)
		if got != "not specified" {
			t.Errorf("HumanDuration(%d) = %q, want %q", m, got, "not specified")
		}
	}
}
