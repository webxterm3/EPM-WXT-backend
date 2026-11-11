package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Local-account inventory storage.
//
// The shape to keep in mind: an agent reports a complete snapshot in one
// message — accounts come in tens, so unlike software there is no chunking —
// and the snapshot both upserts what it found and marks what it did not.
// Nothing is ever deleted, because "who held administrator rights on this
// machine in March" is a question an auditor asks and a delete destroys it.

// ReconcileAccounts writes a complete account snapshot for one machine.
//
// Returns how many rows were created, how many changed, and how many accounts
// the snapshot did not mention and are therefore gone.
//
// The caller must only pass a COMPLETE snapshot. A partial one says nothing
// about what is missing, and the sweep below would read every unreported
// account as deleted — which, for this collection, reads as "those people no
// longer have administrator rights". The agent never sends a failed scan for
// exactly this reason.
func (m *MongoDB) ReconcileAccounts(machine *Machine, scanID string, accounts []LocalAccount, at time.Time) (added, updated, removed int64, err error) {
	if machine == nil {
		return 0, 0, 0, fmt.Errorf("reconciling accounts: no machine")
	}
	// An empty snapshot is refused rather than swept.
	//
	// Every machine has at least root or Administrator, so "no accounts" is
	// never a true answer — it is a broken collector. Sweeping on it would
	// mark every account on the machine as gone, which is the single most
	// destructive thing this function could do, and it would do it quietly.
	if len(accounts) == 0 {
		return 0, 0, 0, fmt.Errorf("reconciling accounts: refusing an empty snapshot for %s", machine.Name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	deduped := dedupeByAccountKey(accounts)
	models := make([]mongo.WriteModel, 0, len(deduped))
	for _, acc := range deduped {
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.M{"agent_id": machine.AgentID, "account_key": acc.AccountKey}).
			SetUpdate(accountUpdate(machine, acc, scanID, at)).
			SetUpsert(true))
	}

	// Unordered so one bad row cannot stop the rest of the snapshot.
	res, err := m.LocalAccounts.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
	if res != nil {
		added, updated = res.UpsertedCount, res.ModifiedCount
	}
	if err != nil {
		return added, updated, 0, fmt.Errorf("writing account snapshot: %w", err)
	}

	removed, err = m.sweepRemovedAccounts(ctx, machine.AgentID, scanID, at)
	if err != nil {
		return added, updated, 0, err
	}
	return added, updated, removed, nil
}

// sweepRemovedAccounts marks everything the given snapshot did not report.
//
// Keyed on the scan marker rather than on a list of usernames, the same way
// the software sweep works: the alternative is a query naming every account
// the machine still has.
//
// admin_since is cleared alongside, because an account that no longer exists
// does not hold administrator rights, and leaving the field set would keep it
// in the "has held local admin since March" evidence after it was deleted.
func (m *MongoDB) sweepRemovedAccounts(ctx context.Context, agentID, scanID string, at time.Time) (int64, error) {
	res, err := m.LocalAccounts.UpdateMany(ctx,
		bson.M{"agent_id": agentID, "present": true, "scan_id": bson.M{"$ne": scanID}},
		bson.M{
			"$set": bson.M{
				"present":    false,
				"is_admin":   false,
				"demotable":  false,
				"removed_at": at,
				"updated_at": at,
			},
			"$unset": bson.M{"admin_since": "", "admin_until": ""},
		})
	if err != nil {
		return 0, fmt.Errorf("sweeping removed accounts: %w", err)
	}
	return res.ModifiedCount, nil
}

// dedupeByAccountKey collapses repeats within one snapshot.
//
// An unordered bulk write with two models matching the same filter can race
// against its own upsert and fail on the unique index. The agent already
// de-duplicates; this is belt-and-braces against a future collector that
// forgets to.
func dedupeByAccountKey(accounts []LocalAccount) []LocalAccount {
	seen := make(map[string]int, len(accounts))
	out := make([]LocalAccount, 0, len(accounts))
	for _, acc := range accounts {
		if i, dup := seen[acc.AccountKey]; dup {
			out[i] = acc // last one wins; they describe the same account
			continue
		}
		seen[acc.AccountKey] = len(out)
		out = append(out, acc)
	}
	return out
}

// accountUpdate builds the upsert for one account, as an aggregation pipeline.
//
// A pipeline rather than a plain $set/$setOnInsert because two fields have to
// be decided from what is already on the row:
//
//   - first_seen must survive every later snapshot.
//   - admin_since must be set when an account gains administrator rights,
//     left alone while it keeps them, and cleared when it loses them. A plain
//     $set would re-stamp it on every scan, turning "has held admin since
//     March" into "has held admin since six hours ago" — which is the same
//     sentence with the evidence removed.
//
// Extracted so it can be checked without a database. The filter and this
// builder have to agree about which fields exist on a row; when they silently
// disagreed in the software inventory — machine_id filtered on but never
// written — every machine's Applications tab came back empty while the agent
// reported happily twice a day.
func accountUpdate(machine *Machine, acc LocalAccount, scanID string, at time.Time) mongo.Pipeline {
	set := bson.D{
		// machine_id is recomputed, not preserved: a machine deleted and
		// re-enrolled against the same registration token gets the same
		// agent_id, so these rows survive and match again — but with the old
		// machine_id, which no longer exists.
		{Key: "machine_id", Value: machine.ID},
		{Key: "machine_name", Value: machine.Name},
		{Key: "tenant_id", Value: machine.TenantID},
		{Key: "agent_id", Value: machine.AgentID},
		{Key: "account_key", Value: acc.AccountKey},

		{Key: "username", Value: acc.Username},
		{Key: "username_lower", Value: strings.ToLower(acc.Username)},
		{Key: "full_name", Value: acc.FullName},
		{Key: "uid", Value: acc.UID},
		{Key: "sid", Value: acc.SID},
		{Key: "is_admin", Value: acc.IsAdmin},
		{Key: "is_local", Value: acc.IsLocal},
		{Key: "demotable", Value: acc.Demotable},
		{Key: "source", Value: acc.Source},
		{Key: "shell", Value: acc.Shell},
		{Key: "home_dir", Value: acc.HomeDir},
		{Key: "disabled", Value: acc.Disabled},
		{Key: "hidden", Value: acc.Hidden},

		{Key: "last_seen", Value: at},
		{Key: "present", Value: true},
		{Key: "scan_id", Value: scanID},
		{Key: "updated_at", Value: at},

		// Keep the original if there is one, otherwise stamp now.
		{Key: "first_seen", Value: bson.M{"$ifNull": bson.A{"$first_seen", at}}},

		// Set on gaining admin, preserved while holding it, removed on losing
		// it. $$REMOVE inside a pipeline $set is how a field is deleted
		// conditionally in the same operation that writes the others.
		{Key: "admin_since", Value: bson.M{
			"$cond": bson.A{
				acc.IsAdmin,
				bson.M{"$ifNull": bson.A{"$admin_since", at}},
				"$$REMOVE",
			},
		}},

		// An account that comes back has to clear its tombstone, or the row
		// stays marked removed while plainly being present.
		{Key: "removed_at", Value: "$$REMOVE"},
	}

	if acc.LastLogin != nil {
		set = append(set, bson.E{Key: "last_login", Value: acc.LastLogin})
	}

	// admin_until is written on EVERY snapshot, set or removed.
	//
	// Appended unconditionally rather than only when present, because the
	// interesting transition is the one where it disappears: a grant that
	// ended must stop being advertised. Writing it only when set would leave
	// the portal showing "administrator until 14:00" long after 14:00, on an
	// account that is now a standard user.
	if acc.AdminUntil != nil && !acc.AdminUntil.IsZero() {
		set = append(set, bson.E{Key: "admin_until", Value: acc.AdminUntil})
	} else {
		set = append(set, bson.E{Key: "admin_until", Value: "$$REMOVE"})
	}

	return mongo.Pipeline{bson.D{{Key: "$set", Value: set}}}
}

// AccountQuery filters an account listing.
type AccountQuery struct {
	// AdminsOnly restricts the result to accounts holding administrator
	// rights, which is the listing the fleet view is built on.
	AdminsOnly bool

	// DemotableOnly further restricts it to accounts policy could act on.
	// Deliberately separate from AdminsOnly: the gap between the two numbers
	// is root and the directory accounts, and an operator sizing a rollout
	// needs to see both.
	DemotableOnly bool

	IncludeRemoved bool
	Search         string
	Limit          int
	Skip           int
}

// GetAccountsByMachine lists one machine's accounts.
func (m *MongoDB) GetAccountsByMachine(machineID primitive.ObjectID, q AccountQuery) ([]*LocalAccount, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	filter := accountFilter(q)
	filter["machine_id"] = machineID

	opts := options.Find().
		SetSort(bson.D{{Key: "is_admin", Value: -1}, {Key: "username_lower", Value: 1}}).
		SetLimit(int64(clampAccountLimit(q.Limit))).
		SetSkip(int64(max0(q.Skip)))

	cur, err := m.LocalAccounts.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("listing accounts: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	var out []*LocalAccount
	if err := cur.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("decoding accounts: %w", err)
	}
	return out, nil
}

// GetAccountsByTenant lists accounts across a tenant's fleet, with the total
// matching count so a listing can be paged honestly.
func (m *MongoDB) GetAccountsByTenant(tenantID string, q AccountQuery) ([]*LocalAccount, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	filter := accountFilter(q)
	filter["tenant_id"] = tenantID

	total, err := m.LocalAccounts.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("counting accounts: %w", err)
	}

	opts := options.Find().
		SetSort(bson.D{
			{Key: "is_admin", Value: -1},
			{Key: "machine_name", Value: 1},
			{Key: "username_lower", Value: 1},
		}).
		SetLimit(int64(clampAccountLimit(q.Limit))).
		SetSkip(int64(max0(q.Skip)))

	cur, err := m.LocalAccounts.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("listing accounts: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	var out []*LocalAccount
	if err := cur.All(ctx, &out); err != nil {
		return nil, 0, fmt.Errorf("decoding accounts: %w", err)
	}
	return out, total, nil
}

// accountFilter builds the shared part of both listings.
func accountFilter(q AccountQuery) bson.M {
	filter := bson.M{}
	if !q.IncludeRemoved {
		filter["present"] = true
	}
	if q.AdminsOnly {
		filter["is_admin"] = true
	}
	if q.DemotableOnly {
		filter["demotable"] = true
	}
	if search := strings.TrimSpace(q.Search); search != "" {
		// Anchored and quoted: an unanchored regex cannot use the index, and
		// an unquoted one lets a search box become a query injection.
		filter["username_lower"] = bson.M{
			"$regex": "^" + regexp.QuoteMeta(strings.ToLower(search)),
		}
	}
	return filter
}

// defaultAccountLimit and maxAccountLimit bound a listing.
//
// A machine has accounts in the tens, so the default covers every real
// machine in one page; the ceiling exists for the fleet listing, where a
// caller asking for everything would otherwise pull a tenant's entire
// estate into one response.
const (
	defaultAccountLimit = 200
	maxAccountLimit     = 1000
)

func clampAccountLimit(limit int) int {
	if limit <= 0 {
		return defaultAccountLimit
	}
	if limit > maxAccountLimit {
		return maxAccountLimit
	}
	return limit
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
