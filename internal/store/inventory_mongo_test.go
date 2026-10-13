package store

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func sampleUpdate(t *testing.T) (set bson.M, onInsert bson.M) {
	t.Helper()
	machine := &Machine{
		ID:       primitive.NewObjectID(),
		AgentID:  "super-admin-2cc6bf8a",
		Name:     "test-win-server",
		TenantID: "super-admin",
	}
	app := InstalledApp{
		AppKey:    "k1",
		Name:      "Google Chrome",
		Publisher: "Google LLC",
		Source:    "windows-registry",
	}
	doc := inventoryUpdate(machine, app, "scan-1", time.Now())

	set, ok := doc["$set"].(bson.M)
	if !ok {
		t.Fatalf("$set missing or not a document: %v", doc)
	}
	onInsert, ok = doc["$setOnInsert"].(bson.M)
	if !ok {
		t.Fatalf("$setOnInsert missing or not a document: %v", doc)
	}
	return set, onInsert
}

// The bug this pins: machine_id was filtered on but never written, so the
// Applications tab was empty on every machine while the agent reported fine.
//
// Written generically — any field the listing filters on must be a field the
// upsert writes — so the next field added to one side cannot quietly go
// missing from the other.
func TestEveryFilteredFieldIsActuallyWritten(t *testing.T) {
	set, onInsert := sampleUpdate(t)

	written := map[string]bool{}
	for k := range set {
		written[k] = true
	}
	for k := range onInsert {
		written[k] = true
	}

	filter := inventoryFilter(primitive.NewObjectID(), InventoryQuery{
		Search: "chrome",
		Source: "windows-registry",
	})

	for field := range filter {
		if field == "$or" {
			// The search clause names its own fields rather than filtering on
			// one, so it is checked separately below.
			continue
		}
		if !written[field] {
			t.Errorf("the listing filters on %q but the upsert never writes it", field)
		}
	}

	// The search branch is the other half of the same contract.
	for _, clause := range filter["$or"].([]bson.M) {
		for field := range clause {
			if !written[field] {
				t.Errorf("search filters on %q but the upsert never writes it", field)
			}
		}
	}
}

// Mongo rejects the whole update if a field appears in both operators, so the
// write fails for every application at once rather than degrading.
func TestSetAndSetOnInsertDoNotOverlap(t *testing.T) {
	set, onInsert := sampleUpdate(t)
	for field := range onInsert {
		if _, clash := set[field]; clash {
			t.Errorf("%q is in both $set and $setOnInsert; Mongo will reject the update", field)
		}
	}
}

// machine_id must follow the machine, not stick to the row it was created
// with: a deleted and re-enrolled machine keeps its agent_id, so these rows
// match again under a machine_id that no longer exists.
func TestMachineIDIsUpdatedNotOnlySetAtInsert(t *testing.T) {
	set, onInsert := sampleUpdate(t)
	if _, ok := set["machine_id"]; !ok {
		t.Error("machine_id is not in $set — a re-enrolled machine keeps a stale one")
	}
	if _, ok := onInsert["machine_id"]; ok {
		t.Error("machine_id is in $setOnInsert — it would never be corrected")
	}
}

// publisher_lower is only written when there is a publisher, so a search must
// not depend on it alone.
func TestSearchIsNotPublisherOnly(t *testing.T) {
	filter := inventoryFilter(primitive.NewObjectID(), InventoryQuery{Search: "chrome"})
	clauses := filter["$or"].([]bson.M)
	if len(clauses) < 2 {
		t.Fatalf("search uses %d clause(s); an app with no publisher would be unfindable", len(clauses))
	}
}
