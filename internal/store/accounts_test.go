package store

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func testMachine() *Machine {
	return &Machine{
		ID:       primitive.NewObjectID(),
		AgentID:  "super-admin-1639100b",
		Name:     "macb",
		TenantID: "tenant-1",
	}
}

// fields flattens the pipeline's single $set stage so a test can ask what the
// update writes without a database.
func fields(t *testing.T, acc LocalAccount) bson.M {
	t.Helper()

	pipeline := accountUpdate(testMachine(), acc, "scan-1", time.Unix(1762758000, 0).UTC())
	if len(pipeline) != 1 {
		t.Fatalf("expected one pipeline stage, got %d", len(pipeline))
	}

	stage := pipeline[0]
	if len(stage) != 1 || stage[0].Key != "$set" {
		t.Fatalf("expected a single $set stage, got %v", stage)
	}

	set, ok := stage[0].Value.(bson.D)
	if !ok {
		t.Fatalf("$set is %T, want bson.D", stage[0].Value)
	}

	out := bson.M{}
	for _, e := range set {
		out[e.Key] = e.Value
	}
	return out
}

// machine_id is recomputed on every snapshot rather than kept from the first.
//
// A machine deleted and re-enrolled against the same registration token gets
// the same agent_id, so its rows survive and match again — but carrying the
// OLD machine_id, which no longer exists. That exact bug emptied every
// machine's Applications tab once already while the agent reported happily
// twice a day.
func TestTheMachineIsRelinkedOnEverySnapshot(t *testing.T) {
	f := fields(t, LocalAccount{AccountKey: "uid:501", Username: "priya"})

	for _, key := range []string{"machine_id", "machine_name", "tenant_id", "agent_id"} {
		if _, ok := f[key]; !ok {
			t.Errorf("%s is not written on every snapshot — a re-enrolled machine would keep a dead link", key)
		}
	}
}

// first_seen must survive every later snapshot, or "has existed since March"
// resets to "has existed since this morning" on every scan.
func TestFirstSeenIsPreservedWhenItExists(t *testing.T) {
	f := fields(t, LocalAccount{AccountKey: "uid:501", Username: "priya"})

	got, ok := f["first_seen"].(bson.M)
	if !ok {
		t.Fatalf("first_seen is %T, want a conditional expression", f["first_seen"])
	}
	if _, ok := got["$ifNull"]; !ok {
		t.Error("first_seen is written unconditionally — it would reset on every scan")
	}
}

// admin_since is the field that turns a list into evidence. It has three
// behaviours and all three matter:
//
//	gaining admin  → stamped now
//	keeping admin  → left exactly as it was
//	losing admin   → removed
//
// A plain $set would collapse the first two, rewriting the date on every
// scan, so "has held local admin since March" would quietly become "since six
// hours ago" — the same sentence with the evidence taken out.
func TestAdminSinceIsConditionalForAnAdministrator(t *testing.T) {
	f := fields(t, LocalAccount{AccountKey: "uid:501", Username: "priya", IsAdmin: true})

	cond, ok := f["admin_since"].(bson.M)
	if !ok {
		t.Fatalf("admin_since is %T, want a conditional expression", f["admin_since"])
	}

	branches, ok := cond["$cond"].(bson.A)
	if !ok || len(branches) != 3 {
		t.Fatalf("admin_since is not a three-branch $cond: %v", cond)
	}
	if branches[0] != true {
		t.Errorf("the condition is %v, want true for an administrator", branches[0])
	}

	keep, ok := branches[1].(bson.M)
	if !ok {
		t.Fatalf("the admin branch is %T, want an $ifNull", branches[1])
	}
	if _, ok := keep["$ifNull"]; !ok {
		t.Error("an administrator's admin_since is overwritten rather than preserved")
	}
}

// Losing administrator rights must REMOVE the field, not blank it. A zero
// time would read as 1 January year one and sort to the top of any "longest
// standing administrator" list.
func TestAdminSinceIsRemovedWhenRightsAreLost(t *testing.T) {
	f := fields(t, LocalAccount{AccountKey: "uid:501", Username: "priya", IsAdmin: false})

	cond := f["admin_since"].(bson.M)
	branches := cond["$cond"].(bson.A)

	if branches[0] != false {
		t.Errorf("the condition is %v, want false for a standard user", branches[0])
	}
	if branches[2] != "$$REMOVE" {
		t.Errorf("the non-admin branch is %v, want $$REMOVE", branches[2])
	}
}

// An account that comes back has to clear its tombstone, or the row stays
// marked removed while plainly being present.
func TestReturningAccountsClearTheirTombstone(t *testing.T) {
	f := fields(t, LocalAccount{AccountKey: "uid:501", Username: "priya"})

	if f["removed_at"] != "$$REMOVE" {
		t.Errorf("removed_at is %v, want $$REMOVE", f["removed_at"])
	}
	if f["present"] != true {
		t.Errorf("present is %v, want true", f["present"])
	}
}

// The listing filters on username_lower, so the update has to write it.
// A filter on a field nothing writes matches nothing, silently.
func TestTheSearchKeyIsWritten(t *testing.T) {
	f := fields(t, LocalAccount{AccountKey: "uid:501", Username: "PRIYA"})

	if f["username_lower"] != "priya" {
		t.Errorf("username_lower is %v, want the lowercased username", f["username_lower"])
	}

	filter := accountFilter(AccountQuery{Search: "PRIYA"})
	if _, ok := filter["username_lower"]; !ok {
		t.Error("the listing filters on a field the update does not write")
	}
}

// The two filters are separate on purpose: the gap between "administrators"
// and "administrators policy could act on" is root and the directory
// accounts, and an operator sizing a rollout needs both numbers.
func TestTheTwoAdminFiltersAreDistinct(t *testing.T) {
	admins := accountFilter(AccountQuery{AdminsOnly: true})
	if admins["is_admin"] != true {
		t.Error("admins_only does not filter on is_admin")
	}
	if _, narrowed := admins["demotable"]; narrowed {
		t.Error("admins_only also filtered on demotable — the two counts would always be equal")
	}

	eligible := accountFilter(AccountQuery{DemotableOnly: true})
	if eligible["demotable"] != true {
		t.Error("demotable_only does not filter on demotable")
	}
}

// Removed rows are hidden by default. They are kept rather than deleted so
// "who held administrator rights in March" survives the account being
// deleted, but they must not pad the present-day count.
func TestRemovedAccountsAreHiddenUnlessAskedFor(t *testing.T) {
	if accountFilter(AccountQuery{})["present"] != true {
		t.Error("a default listing includes deleted accounts")
	}
	if _, ok := accountFilter(AccountQuery{IncludeRemoved: true})["present"]; ok {
		t.Error("include_removed still filtered on present")
	}
}

// A caller asking for everything must not be able to pull a tenant's entire
// estate into one response.
func TestTheListingLimitIsBounded(t *testing.T) {
	if got := clampAccountLimit(0); got != defaultAccountLimit {
		t.Errorf("no limit gave %d, want the default %d", got, defaultAccountLimit)
	}
	if got := clampAccountLimit(100000); got != maxAccountLimit {
		t.Errorf("an absurd limit gave %d, want the ceiling %d", got, maxAccountLimit)
	}
	if got := clampAccountLimit(50); got != 50 {
		t.Errorf("a reasonable limit was changed to %d", got)
	}
}

func TestDuplicateAccountKeysCollapse(t *testing.T) {
	out := dedupeByAccountKey([]LocalAccount{
		{AccountKey: "uid:501", Username: "priya"},
		{AccountKey: "uid:501", Username: "priya", IsAdmin: true},
		{AccountKey: "uid:502", Username: "amit"},
	})

	if len(out) != 2 {
		t.Fatalf("collapsed to %d rows, want 2", len(out))
	}
	// Last one wins: an unordered bulk write with two models matching the
	// same filter would otherwise race against its own upsert.
	if !out[0].IsAdmin {
		t.Error("the later record did not win the collapse")
	}
}

// admin_until is written on every snapshot, set or removed.
//
// The interesting transition is the one where it disappears: a grant that
// ended must stop being advertised. Writing it only when present would leave
// the portal showing "administrator until 14:00" long after 14:00, on an
// account that is now a standard user.
func TestTheGrantExpiryIsClearedWhenItEnds(t *testing.T) {
	ends := time.Unix(1762758000, 0).UTC()

	withGrant := fields(t, LocalAccount{AccountKey: "uid:501", Username: "priya", AdminUntil: &ends})
	if withGrant["admin_until"] == "$$REMOVE" {
		t.Error("a live grant's expiry was removed")
	}

	without := fields(t, LocalAccount{AccountKey: "uid:501", Username: "priya"})
	if without["admin_until"] != "$$REMOVE" {
		t.Errorf("admin_until = %v; an ended grant would go on being advertised",
			without["admin_until"])
	}
}
