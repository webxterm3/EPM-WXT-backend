package api

import (
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

var now = at("2026-11-11T10:00:00Z")

// No end at all is a real choice, not an omission. Some accounts are supposed
// to be administrators, and the caller has to be able to tell that apart from
// a refusal.
func TestNoDurationMeansNoExpiry(t *testing.T) {
	until, err := grantEnd(accountActionBody{}, now)

	if err != nil {
		t.Fatalf("a grant with no end was refused: %v", err)
	}
	if until != nil {
		t.Errorf("until = %v, want nil for a permanent grant", until)
	}
}

func TestADurationIsCountedFromNow(t *testing.T) {
	until, err := grantEnd(accountActionBody{DurationMinutes: 60}, now)

	if err != nil {
		t.Fatalf("grantEnd: %v", err)
	}
	if !until.Equal(now.Add(time.Hour)) {
		t.Errorf("until = %v, want one hour from now", until)
	}
}

// The timezone case this exists for: an administrator in Kolkata picks
// 17:00 their time. The browser sends it with its offset. The instant that
// reaches the endpoint has to be the one they chose, not 17:00 wherever the
// server happens to run.
func TestAnAbsoluteTimeKeepsTheInstantTheAdministratorChose(t *testing.T) {
	// 17:00 on 11 November in +05:30 is 11:30 UTC.
	chosen := at("2026-11-11T17:00:00+05:30")

	until, err := grantEnd(accountActionBody{Until: &chosen}, now)
	if err != nil {
		t.Fatalf("grantEnd: %v", err)
	}

	if !until.Equal(at("2026-11-11T11:30:00Z")) {
		t.Errorf("until = %v, want the same instant expressed in UTC", until)
	}
	// Normalised to UTC so that everything downstream — the audit entry, the
	// agent, the comparison against the endpoint's clock — reads one zone.
	if until.Location() != time.UTC {
		t.Errorf("until is in %v, want UTC", until.Location())
	}
}

// The same wall clock in a different zone is a different instant, and the
// difference has to survive.
func TestTheSameWallClockInTwoZonesGivesTwoInstants(t *testing.T) {
	kolkata := at("2026-11-11T17:00:00+05:30")
	newYork := at("2026-11-11T17:00:00-05:00")

	a, err := grantEnd(accountActionBody{Until: &kolkata}, now)
	if err != nil {
		t.Fatalf("grantEnd: %v", err)
	}
	b, err := grantEnd(accountActionBody{Until: &newYork}, now)
	if err != nil {
		t.Fatalf("grantEnd: %v", err)
	}

	if a.Equal(*b) {
		t.Error("two different zones produced the same instant — the offset was discarded")
	}
}

// A browser with a wrong clock, or an administrator picking yesterday.
func TestAnEndTimeInThePastIsRefused(t *testing.T) {
	past := now.Add(-time.Hour)

	if _, err := grantEnd(accountActionBody{Until: &past}, now); err == nil {
		t.Error("an end time in the past was accepted")
	}
}

func TestATooShortGrantIsRefused(t *testing.T) {
	soon := now.Add(time.Minute)

	if _, err := grantEnd(accountActionBody{Until: &soon}, now); err == nil {
		t.Error("a one-minute grant was accepted — the rights would end before " +
			"the person finished what they asked for them to do")
	}
	if _, err := grantEnd(accountActionBody{DurationMinutes: 1}, now); err == nil {
		t.Error("a one-minute duration was accepted")
	}
}

// Beyond this it is not a temporary grant, it is standing privilege with an
// end date nobody will remember.
func TestATooLongGrantIsRefused(t *testing.T) {
	far := now.Add(30 * 24 * time.Hour)

	if _, err := grantEnd(accountActionBody{Until: &far}, now); err == nil {
		t.Error("a month-long grant was accepted as temporary")
	}
	if _, err := grantEnd(accountActionBody{DurationMinutes: 30 * 24 * 60}, now); err == nil {
		t.Error("a month-long duration was accepted")
	}
}

func TestTheCeilingIsInclusiveAtItsEdge(t *testing.T) {
	edge := now.Add(maxGrantHours * time.Hour)

	if _, err := grantEnd(accountActionBody{Until: &edge}, now); err != nil {
		t.Errorf("a grant at exactly the ceiling was refused: %v", err)
	}
}

// They can only both arrive through a client bug, and the absolute time is
// the one an administrator actually looked at and chose.
func TestAnAbsoluteTimeWinsOverADuration(t *testing.T) {
	chosen := now.Add(2 * time.Hour)

	until, err := grantEnd(accountActionBody{Until: &chosen, DurationMinutes: 15}, now)
	if err != nil {
		t.Fatalf("grantEnd: %v", err)
	}
	if !until.Equal(chosen.UTC()) {
		t.Errorf("until = %v, want the explicitly chosen time", until)
	}
}

// A negative duration is a client bug, and the safe reading of it is "no
// grant end was asked for" rather than "a grant ending in the past".
func TestANegativeDurationIsTreatedAsNoExpiry(t *testing.T) {
	until, err := grantEnd(accountActionBody{DurationMinutes: -60}, now)

	if err != nil {
		t.Fatalf("grantEnd: %v", err)
	}
	if until != nil {
		t.Errorf("until = %v, want nil", until)
	}
}
