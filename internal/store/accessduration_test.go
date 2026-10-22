package store

import "testing"

// Durations were stored as an int of HOURS in which zero meant NEVER EXPIRES.
//
// Both halves of that were traps. Fifteen minutes could not be expressed at
// all — it rounded to zero — so the shortest window the product offered handed
// out PERMANENT access, which is the exact opposite of what somebody picking
// it was asking for. And a client that simply omitted the field got the same.
func TestMinutesReadsBothEncodings(t *testing.T) {
	t.Run("a request stored in minutes", func(t *testing.T) {
		ar := &AccessRequest{DurationMinutes: 15}
		if got := ar.Minutes(); got != 15 {
			t.Errorf("got %d minutes, want 15", got)
		}
	})

	t.Run("a request stored in hours, before minutes existed", func(t *testing.T) {
		ar := &AccessRequest{DurationHours: 2}
		if got := ar.Minutes(); got != 120 {
			t.Errorf("got %d minutes, want 120", got)
		}
	})

	t.Run("minutes win when a client sent both", func(t *testing.T) {
		ar := &AccessRequest{DurationMinutes: 15, DurationHours: 99}
		if got := ar.Minutes(); got != 15 {
			t.Errorf("got %d — the precise field must win over the rounded one", got)
		}
	})
}

// The old unbounded grants still exist in the database and still mean what
// they meant. Naming the condition keeps it from being a silent property of
// the number zero, which is how it went unnoticed.
func TestAnUnboundedGrantIsNamedRatherThanImplied(t *testing.T) {
	old := &AccessRequest{DurationHours: 0, DurationMinutes: 0}
	if !old.NeverExpires() {
		t.Error("a request stored with no duration at all is one of the old " +
			"unbounded grants and must be recognisable as one")
	}

	for _, ar := range []*AccessRequest{
		{DurationMinutes: 15},
		{DurationHours: 1},
		{DurationMinutes: 1},
	} {
		if ar.NeverExpires() {
			t.Errorf("%+v was treated as unbounded", ar)
		}
	}
}

// A fifteen-minute request must not round to nothing anywhere in the chain.
func TestTheShortestWindowSurvives(t *testing.T) {
	ar := &AccessRequest{DurationMinutes: 1}
	if ar.Minutes() != 1 {
		t.Errorf("one minute became %d", ar.Minutes())
	}
	if ar.NeverExpires() {
		t.Error("the shortest possible request was read as permanent access — " +
			"this is the exact bug the minutes field exists to remove")
	}
}
