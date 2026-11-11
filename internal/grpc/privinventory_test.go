package grpc

import (
	"encoding/json"
	"testing"
)

// decode is how a report reaches the handler: as JSON off the wire, not as a
// struct built in a test. Several of the cases below are about what happens
// when a field is ABSENT, which a struct literal cannot express.
func decode(t *testing.T, raw string) privReport {
	t.Helper()
	var r privReport
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("decoding the report: %v", err)
	}
	return r
}

const oneAdmin = `{
  "collected_at": "2026-11-10T09:00:00Z",
  "os": "darwin",
  "admin_group": "admin",
  "accounts": [
    {"id":"uid:0","username":"root","uid":0,"is_admin":true,"is_local":true,"source":"local"},
    {"id":"uid:502","username":"priya","uid":502,"is_admin":true,"is_local":true,"source":"local"},
    {"id":"uid:503","username":"amit","uid":503,"is_admin":false,"is_local":true,"source":"local"}
  ]
}`

// An empty snapshot is never true: every machine has at least root or
// Administrator. Accepting one would sweep every account on the machine as
// gone, which for this collection reads as "those people no longer have
// administrator rights".
func TestAnEmptySnapshotIsRejected(t *testing.T) {
	r := decode(t, `{"os":"darwin","accounts":[]}`)
	if err := r.validate(); err == nil {
		t.Error("a report with no accounts was accepted")
	}
}

// A well-formed report in which nobody is an administrator cannot be true
// either — it means the membership check failed while the account listing
// succeeded. Stored, it would show the machine as already locked down.
func TestASnapshotWithNoAdministratorIsRefused(t *testing.T) {
	r := decode(t, `{"os":"darwin","accounts":[
		{"id":"uid:503","username":"amit","uid":503,"is_admin":false,"is_local":true}
	]}`)

	if err := r.validate(); err != nil {
		t.Fatalf("the report is well-formed and should pass validate: %v", err)
	}
	if r.hasAdministrator() {
		t.Error("a snapshot with no administrator was accepted as one")
	}
}

func TestAnOrdinarySnapshotIsAccepted(t *testing.T) {
	r := decode(t, oneAdmin)
	if err := r.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !r.hasAdministrator() {
		t.Error("root and priya are both administrators")
	}
}

func TestAnAbsurdlyLargeReportIsRejected(t *testing.T) {
	accounts := make([]privAccount, maxReportedAccounts+1)
	for i := range accounts {
		accounts[i] = privAccount{ID: "uid:1", Username: "x", IsAdmin: true}
	}
	r := privReport{Accounts: accounts}

	if err := r.validate(); err == nil {
		t.Error("a report far past the ceiling was accepted")
	}
}

// Records with no identity cannot be reconciled against the next snapshot;
// records with no username cannot be displayed or named in a policy.
func TestUnusableAccountRecordsAreDropped(t *testing.T) {
	r := decode(t, `{"os":"darwin","accounts":[
		{"id":"uid:0","username":"root","uid":0,"is_admin":true,"is_local":true},
		{"id":"","username":"ghost","uid":600,"is_admin":true,"is_local":true},
		{"id":"uid:601","username":"   ","uid":601,"is_admin":true,"is_local":true}
	]}`)

	got := r.toLocalAccounts()
	if len(got) != 1 {
		t.Fatalf("kept %d accounts, want only root", len(got))
	}
	if got[0].Username != "root" {
		t.Errorf("kept %q", got[0].Username)
	}
}

// demotable is the backend's own copy of the agent's eligibility rule, used
// so the simulation can answer for machines that are offline. Each way of
// being exempt is pinned, because every one of them is somebody who would be
// counted into a rollout that will not move them.

func TestRootIsNotDemotable(t *testing.T) {
	if demotable(privAccount{Username: "root", UID: 0, IsAdmin: true, IsLocal: true}) {
		t.Error("demoting root destroys the machine")
	}
}

func TestTheSystemUIDBoundaryMatchesTheAgent(t *testing.T) {
	if demotable(privAccount{UID: 500, IsAdmin: true, IsLocal: true}) {
		t.Error("UID 500 is the system ceiling and must be exempt")
	}
	if !demotable(privAccount{UID: 501, IsAdmin: true, IsLocal: true}) {
		t.Error("UID 501 is the first real person and must be eligible")
	}
}

func TestADirectoryAccountIsNotDemotable(t *testing.T) {
	if demotable(privAccount{UID: 1501, IsAdmin: true, IsLocal: false}) {
		t.Error("a directory account's rights cannot be removed by a local group edit")
	}
}

func TestANonAdminIsNotDemotable(t *testing.T) {
	if demotable(privAccount{UID: 501, IsAdmin: false, IsLocal: true}) {
		t.Error("an account with no administrator rights has nothing to remove")
	}
}

// Windows accounts arrive with UID 0, which the Unix rule would read as root.
// The SID branch has to be taken, or every Windows account on the fleet is
// exempt and least privilege silently does nothing there.
func TestWindowsAccountsAreJudgedBySIDNotUID(t *testing.T) {
	person := privAccount{
		Username: "priya", UID: 0,
		SID:     "S-1-5-21-1004336348-1177238915-682003330-1103",
		IsAdmin: true, IsLocal: true,
	}
	if !demotable(person) {
		t.Error("an ordinary Windows administrator was treated as root because its UID is 0")
	}

	builtin := person
	builtin.SID = "S-1-5-21-1004336348-1177238915-682003330-500"
	if demotable(builtin) {
		t.Error("the built-in Administrator (RID 500) must be exempt")
	}
}

// A SID ending in 1500 ends with the characters "500". Matching on the digits
// rather than on the RID boundary would exempt a real person — and they would
// simply never be demoted, with nothing in any log to say why.
func TestASIDEndingInThoseDigitsIsNotTheBuiltIn(t *testing.T) {
	a := privAccount{
		Username: "priya",
		SID:      "S-1-5-21-1004336348-1177238915-682003330-1500",
		IsAdmin:  true, IsLocal: true,
	}
	if !demotable(a) {
		t.Error("RID 1500 is an ordinary account, not the built-in Administrator")
	}
}

// is_local absent from the payload decodes to false, which makes an account
// non-demotable. That is the safe direction and is worth pinning: the unsafe
// direction would be defaulting it to true and demoting directory accounts.
func TestAMissingIsLocalIsNotTreatedAsLocal(t *testing.T) {
	r := decode(t, `{"os":"darwin","accounts":[
		{"id":"uid:501","username":"priya","uid":501,"is_admin":true}
	]}`)

	got := r.toLocalAccounts()
	if len(got) != 1 {
		t.Fatalf("expected the account to be kept, got %d", len(got))
	}
	if got[0].Demotable {
		t.Error("an account whose is_local never arrived was treated as demotable")
	}
}

// The scan marker is minted server-side so a machine cannot replay one to
// make an older snapshot look current. Two calls must differ, or the sweep
// would skip rows that the new snapshot did not mention.
func TestEachScanGetsItsOwnMarker(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newPrivScanID()
		if id == "" {
			t.Fatal("empty scan marker")
		}
		if seen[id] {
			t.Fatalf("duplicate scan marker %q after %d draws", id, i)
		}
		seen[id] = true
	}
}
