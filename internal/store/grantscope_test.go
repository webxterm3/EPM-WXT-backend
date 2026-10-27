package store

import "testing"

// Approving an install must not hand out remote access.
//
// machine.AllowedUsers is the remote-access list — api/terminal.go checks it
// to decide who may open a session on a machine. Approving every request
// wrote the requester into it, so "let me install Visual Studio Code" also
// granted access to the Mac. On an endpoint-raised request the name written
// there is the macOS console account, not a portal user, so it would match
// any portal user who happened to share the name.
func TestApprovingAnInstallDoesNotGrantRemoteAccess(t *testing.T) {
	asks := AccessAsks{AppInstall: &AppInstallAsk{
		Applications: []string{"Visual Studio Code"},
	}}
	if asks.GrantsMachineAccess() {
		t.Error("approving an install request added the requester to the " +
			"machine's remote-access list")
	}
}

// What the list is actually for still works.
func TestApprovingRemoteSupportDoesGrantAccess(t *testing.T) {
	support := AccessAsks{RemoteSupport: &RemoteSupportAsk{Control: "view"}}
	if !support.GrantsMachineAccess() {
		t.Error("approving a remote-support request granted no access, so the " +
			"session it was approved for cannot be opened")
	}
	admin := AccessAsks{AdminAccess: &AdminAccessAsk{}}
	if !admin.GrantsMachineAccess() {
		t.Error("approving an admin-access request granted no access")
	}
}

// One request can carry more than one ask; the install must not suppress the
// access the other ask was approved for.
func TestAnInstallAlongsideRemoteSupportStillGrantsAccess(t *testing.T) {
	both := AccessAsks{
		RemoteSupport: &RemoteSupportAsk{Control: "control"},
		AppInstall:    &AppInstallAsk{Applications: []string{"Docker"}},
	}
	if !both.GrantsMachineAccess() {
		t.Error("an install ask alongside remote support suppressed the access " +
			"that was asked for and approved")
	}
}

// A request stored before asks existed was a remote-access request. Changing
// what an existing grant means, in either direction, is a decision for
// whoever made it.
func TestARequestFromBeforeAsksKeepsItsOldMeaning(t *testing.T) {
	if !(AccessAsks{}).GrantsMachineAccess() {
		t.Error("a request stored before the asks field silently stopped " +
			"granting the access it was approved for")
	}
}

// The grant and the revoke must ask the SAME question.
//
// Narrowing one without the other would have an expiring install-only
// request strip access somebody holds from a different request that is
// still live — a permission disappearing for a reason nobody can trace.
func TestTheGrantAndTheRevokeAskTheSameQuestion(t *testing.T) {
	for _, rel := range []string{"../api/access_requests.go", "../../cmd/server/main.go"} {
		src := readFileForTest(t, rel)
		if countOutside(src, "RevokeMachineAccess(") == 0 {
			continue
		}
		if !containsText(src, "GrantsMachineAccess()") {
			t.Errorf("%s revokes machine access without asking whether the "+
				"request granted it", rel)
		}
	}
}
