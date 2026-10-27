package grpc

import (
	"regexp"
	"strings"
	"testing"
)

// Exceptions are attached in exactly one place, so there is exactly one place
// that may send a policy.
//
// There used to be two senders. pushResolved attached ApprovedInstalls;
// PushTo resolved and marshalled its own copy and did not — under a comment
// asserting that the two "cannot drift", which is the kind of claim that
// stops anybody checking. PushTo is what the on-connect push and the menu
// bar's "Sync Now" both call, so in practice an approval reached a Mac only
// if an administrator happened to edit some policy afterwards and set off a
// tenant-wide sweep. Approving a request delivered a policy with no
// exceptions in it and the endpoint went on refusing the software.
//
// Nothing failed. That is why this is a test and not a comment.
func TestOnlyOnePlaceSendsAPolicy(t *testing.T) {
	src := readFile(t, "internal/grpc/apppolicy.go")

	senders := callersOf(src, "SendAppPolicy")
	if len(senders) != 1 {
		t.Fatalf("%d functions send an application policy (%s); every one that is "+
			"not pushResolved sends it WITHOUT the approved installs attached",
			len(senders), strings.Join(senders, ", "))
	}
	if senders[0] != "pushResolved" {
		t.Errorf("the policy is sent from %s, which is not where exceptions are "+
			"attached", senders[0])
	}
}

// And the one sender must actually attach them.
func TestTheSenderAttachesTheApprovedInstalls(t *testing.T) {
	body := between(t, readFile(t, "internal/grpc/apppolicy.go"),
		"func (p *PolicyPusher) pushResolved", "\nfunc ")

	// Matched on the assignment, not on the whole call, so adding an
	// argument does not look like the guard being removed.
	if !strings.Contains(body, "ApprovedInstalls = p.approvedInstallsFor(") {
		t.Error("pushResolved no longer attaches the machine's approved installs, " +
			"so an approval can never take effect on any endpoint")
	}
}

// callersOf names the top-level functions whose body mentions a call.
func callersOf(src, call string) []string {
	funcAt := regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?(\w+)\(`)
	locs := funcAt.FindAllStringSubmatchIndex(src, -1)

	var found []string
	for i, loc := range locs {
		end := len(src)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		if strings.Contains(src[loc[1]:end], call+"(") {
			found = append(found, src[loc[2]:loc[3]])
		}
	}
	return found
}
