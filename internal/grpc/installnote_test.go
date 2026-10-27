package grpc

import (
	"strings"
	"testing"
)

// What the approver reads has to make sense in the case that actually
// happens most.
//
// In a default-deny estate nobody has written a rule about most software, so
// Evaluate returns the default action with Rule and PolicyName unset. The
// note used to be one fixed shape that interpolated them regardless, and
// rendered `was blocked by the rule "" in policy ""` — which reads as a
// fault in the product, at the exact moment somebody is being asked to trust
// it enough to approve something.
func TestTheNoteMakesSenseWhenNoRuleMatched(t *testing.T) {
	note := installRequestNote(endpointInstallRequest{
		Application: "Visual Studio Code",
		OSUser:      "yesveer",
	}, "Yesveer's MacBook Pro")

	if strings.Contains(note, `""`) {
		t.Errorf("the note shows an empty quoted name: %q", note)
	}
	for _, want := range []string{"Visual Studio Code", "Yesveer's MacBook Pro", "yesveer"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not say %q: %q", want, note)
		}
	}
}

// And when a rule DID match, the approver is told which one — that is the
// difference between "somebody wants this" and "your policy refused this".
func TestTheNoteNamesTheRuleThatRefusedIt(t *testing.T) {
	note := installRequestNote(endpointInstallRequest{
		Application: "qBittorrent",
		OSUser:      "yesveer",
		Rule:        "No peer-to-peer clients",
		Policy:      "Corporate baseline",
	}, "Yesveer's MacBook Pro")

	for _, want := range []string{"No peer-to-peer clients", "Corporate baseline"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not name %q: %q", want, note)
		}
	}
}

// An endpoint that could not tell who was at the screen still produces a
// readable note rather than a dangling sentence.
func TestTheNoteReadsWhenNobodyCouldBeNamed(t *testing.T) {
	note := installRequestNote(endpointInstallRequest{Application: "Docker"}, "build-01")
	if strings.Contains(note, "when  opened") || strings.Contains(note, "by  opened") {
		t.Errorf("the note has a hole where the person's name goes: %q", note)
	}
}
