package api

import (
	"testing"
	"time"
)

func rfc(t time.Time) string { return t.Format(time.RFC3339) }

// A window that has already closed must be refused, not stored.
//
// Stored, it sits in the queue looking schedulable, and an approver clicking
// it creates a grant that expired before it existed — a request that was
// approved and never worked, with nothing anywhere saying why.
func TestAWindowThatHasAlreadyClosedIsRefused(t *testing.T) {
	past := time.Now().Add(-time.Hour)

	if _, _, err := parseWindow("", rfc(past)); err == nil {
		t.Error("a window ending in the past was accepted")
	}
}

// Ending before it starts is a typo, and the grant it would produce has a
// negative length.
func TestAWindowMustEndAfterItStarts(t *testing.T) {
	start := time.Now().Add(2 * time.Hour)
	end := time.Now().Add(time.Hour)

	if _, _, err := parseWindow(rfc(start), rfc(end)); err == nil {
		t.Error("a window ending before it starts was accepted")
	}
	if _, _, err := parseWindow(rfc(start), rfc(start)); err == nil {
		t.Error("a zero-length window was accepted — the grant would be over on arrival")
	}
}

// A start in the past is the same as no start. Kept, it would make the
// request look scheduled when it is not, and the countdown would appear to
// have begun before anybody approved it.
func TestAStartInThePastIsTreatedAsNoStart(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)

	from, to, err := parseWindow(rfc(past), rfc(future))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if from != nil {
		t.Errorf("a start in the past was kept as %v", from)
	}
	if to == nil {
		t.Error("the end of the window was dropped along with it")
	}
}

func TestNoWindowIsNotAnError(t *testing.T) {
	from, to, err := parseWindow("", "")
	if err != nil {
		t.Fatalf("an absent window was an error: %v", err)
	}
	if from != nil || to != nil {
		t.Error("an absent window produced timestamps")
	}
}

func TestAMalformedTimestampSaysWhichField(t *testing.T) {
	if _, _, err := parseWindow("not a time", ""); err == nil {
		t.Error("a malformed start was accepted")
	} else if got := err.Error(); got != "not_before must be an RFC3339 timestamp" {
		t.Errorf("error %q does not name the field that is wrong", got)
	}

	if _, _, err := parseWindow("", "also not a time"); err == nil {
		t.Error("a malformed end was accepted")
	} else if got := err.Error(); got != "not_after must be an RFC3339 timestamp" {
		t.Errorf("error %q does not name the field that is wrong", got)
	}
}

// A valid future window survives intact — the duration is derived from it, so
// losing either end silently changes how long the grant lasts.
func TestAValidWindowIsKeptAsGiven(t *testing.T) {
	start := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	end := start.Add(90 * time.Minute)

	from, to, err := parseWindow(rfc(start), rfc(end))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if from == nil || to == nil {
		t.Fatal("a valid window was dropped")
	}
	if got := to.Sub(*from); got != 90*time.Minute {
		t.Errorf("the window is %v long, want 90m — the duration is taken from this", got)
	}
}
