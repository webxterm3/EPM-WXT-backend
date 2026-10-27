package api

import (
	"testing"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// "Active" is a session that is running. An install is not one.
//
// A request to install software is finished for the approver the moment they
// decide — there is no window to watch, nothing to revoke mid-way, nobody to
// cut off. Leaving it in Active filled an administrator's queue with rows
// that sat there for a day and then turned into "expired", which reads as
// nobody having dealt with them.
func TestInstallingIsTheWholeOfSomeRequests(t *testing.T) {
	if !installOnly(store.AccessAsks{
		AppInstall: &store.AppInstallAsk{Applications: []string{"Slack"}},
	}) {
		t.Error("a request that only asks to install software is treated as a " +
			"session, so it sits in Active until it expires")
	}
}

// But one that also asks for remote support HAS a session to run, and that
// one is genuinely active — it can be watched, and it can be revoked.
func TestARequestWithASessionIsNotInstallOnly(t *testing.T) {
	for _, asks := range []store.AccessAsks{
		{
			AppInstall:    &store.AppInstallAsk{Applications: []string{"Slack"}},
			RemoteSupport: &store.RemoteSupportAsk{Control: "view"},
		},
		{
			AppInstall:  &store.AppInstallAsk{Applications: []string{"Slack"}},
			AdminAccess: &store.AdminAccessAsk{},
		},
	} {
		if installOnly(asks) {
			t.Error("a request carrying a session was finished the moment it " +
				"was approved, so the session can never be revoked")
		}
	}
}

// And a request that asks for no install at all is not one of these.
func TestARequestWithNoInstallIsNotInstallOnly(t *testing.T) {
	if installOnly(store.AccessAsks{RemoteSupport: &store.RemoteSupportAsk{}}) {
		t.Error("a remote-support request was treated as an install")
	}
	if installOnly(store.AccessAsks{}) {
		t.Error("a request from before asks existed was treated as an install")
	}
}
