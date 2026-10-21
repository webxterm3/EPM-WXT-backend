package store

import "testing"

// The key IS the suppression. Everything that distinguishes one alert from
// another has to be in it, and nothing else may be — a timestamp or an event
// id would make every claim unique, which turns the deduplication off while
// leaving every part of the system looking correct.
func TestNotificationKeyDistinguishesWhatMatters(t *testing.T) {
	base := NotificationKey("elevation", "granted", "t1", "agent-1", "Docker Desktop")

	t.Run("the same alert claims the same key", func(t *testing.T) {
		if again := NotificationKey("elevation", "granted", "t1", "agent-1", "Docker Desktop"); again != base {
			t.Errorf("two reports of the same condition built different keys:\n  %s\n  %s", base, again)
		}
	})

	differs := map[string][]string{
		"a different application": {"elevation", "granted", "t1", "agent-1", "Figma"},
		"a different machine":     {"elevation", "granted", "t1", "agent-2", "Docker Desktop"},
		"a different tenant":      {"elevation", "granted", "t2", "agent-1", "Docker Desktop"},
		"a different kind":        {"elevation", "unavailable", "t1", "agent-1", "Docker Desktop"},
	}
	for name, parts := range differs {
		t.Run(name+" is a different alert", func(t *testing.T) {
			if got := NotificationKey(parts...); got == base {
				t.Errorf("%s produced the same key, so one of the two alerts would be silently suppressed:\n  %s", name, got)
			}
		})
	}
}

// The separator must not be forgeable out of a part, or two unrelated alerts
// collide and one is never sent. Application names come off the endpoint, from
// a bundle's own Info.plist or a PE header — files a local user can author, so
// a name containing the separator is attacker-chosen, not hypothetical.
func TestASeparatorInAPartCannotForgeACollision(t *testing.T) {
	// Without the substitution these are both "x|a|b": machine "a" plus app
	// "b" versus a machine literally named "a|b".
	viaTwoParts := NotificationKey("x", "a", "b")
	viaOnePart := NotificationKey("x", "a|b")

	if viaTwoParts == viaOnePart {
		t.Errorf("an application name containing the separator collided with a "+
			"different machine's alert, which would silence one of them:\n  %s", viaTwoParts)
	}
}

// Empty parts must still occupy their position. Collapsing them would let a
// report with no application name claim the key of one that has it.
func TestEmptyPartsHoldTheirPlace(t *testing.T) {
	withBlank := NotificationKey("a", "", "c")
	shifted := NotificationKey("a", "c")

	if withBlank == shifted {
		t.Errorf("a missing field collapsed the key, so an event with no application "+
			"name would suppress a different alert:\n  %s", withBlank)
	}
	if NotificationKey("a", "   ", "c") != withBlank {
		t.Error("whitespace and empty produced different keys — the same missing field " +
			"would then claim two keys and be mailed twice")
	}
}
