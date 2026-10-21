package store

import (
	"context"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Application-control enforcement: the per-tenant switch, and the record of
// what endpoints did once it was on.
//
// The switch is its own small collection rather than a field on TenantConfig
// for the same reason policies are: that document is written whole with $set,
// so adding a field to it means every unrelated save is one missed re-read
// away from silently turning enforcement off across a tenant.

// GetAppControlSettings returns a tenant's enforcement settings.
//
// A tenant that has never chosen gets the zero value, which is enforcement
// off. That default is load-bearing: a tenant created before this existed, or
// one whose settings document fails to read, must end up not enforcing.
func (m *MongoDB) GetAppControlSettings(tenantID string) (*AppControlSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var s AppControlSettings
	err := m.AppControlSettings.FindOne(ctx, bson.M{"tenant_id": tenantID}).Decode(&s)
	if err != nil {
		// Absent is the normal state, not a failure.
		return &AppControlSettings{TenantID: tenantID}, nil
	}
	return &s, nil
}

// SetAppControlEnforcement turns enforcement on or off for a tenant.
func (m *MongoDB) SetAppControlEnforcement(tenantID string, enabled bool, actor string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	_, err := m.AppControlSettings.UpdateOne(ctx,
		bson.M{"tenant_id": tenantID},
		bson.M{
			// Only the fields this call owns. Spelled out rather than $set of
			// the whole struct so that a future setting on this document is
			// not zeroed by a caller that predates it.
			"$set": bson.M{
				"enforcement": enabled,
				"updated_at":  now,
				"updated_by":  actor,
			},
			"$setOnInsert": bson.M{"tenant_id": tenantID},
		},
		options.Update().SetUpsert(true))
	return err
}

// RecordEnforcementEvents stores what an agent reported doing.
//
// Insert-only and never updated: this is a record of things that have already
// happened on somebody's machine, and the value of it depends entirely on it
// not being rewritable after the fact.
func (m *MongoDB) RecordEnforcementEvents(events []EnforcementEvent) error {
	if len(events) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	docs := make([]any, 0, len(events))
	for i := range events {
		if events[i].CreatedAt.IsZero() {
			events[i].CreatedAt = time.Now()
		}
		docs = append(docs, events[i])
	}

	// Unordered: one malformed event must not discard the rest of the batch,
	// which would lose the record of blocks that genuinely happened.
	_, err := m.EnforcementEvents.InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
	return err
}

// enforcementEventFilter builds the query for one listing.
//
// Separated from the database call so it can be tested on its own: the
// interesting mistakes here — dropping the tenant scope, letting typed text
// reach the engine as a pattern, searching the wrong fields — are all
// mistakes in this value, and none of them need a database to catch.
func enforcementEventFilter(q EnforcementEventQuery) bson.M {
	filter := bson.M{"tenant_id": q.TenantID}
	if q.AgentID != "" {
		filter["agent_id"] = q.AgentID
	}

	search := strings.TrimSpace(q.Search)
	if search == "" {
		return filter
	}

	// QuoteMeta, always. Enforcement activity is mostly file paths, and paths
	// are full of regex metacharacters: "C:\Program Files (x86)\…" is an
	// unbalanced group that makes the whole query error, and a lone "." from
	// somebody typing an extension matches every row in the tenant. Escaped,
	// each one searches for itself.
	re := primitive.Regex{Pattern: regexp.QuoteMeta(search), Options: "i"}

	// $or sits beside the tenant scope, not instead of it: the whole filter is
	// an AND, so a search can only ever narrow what this tenant may already
	// see. It can never reach another tenant's history.
	filter["$or"] = []bson.M{
		{"app_name": re},
		{"path": re},
		{"rule": re},
		{"policy": re},
		{"machine_name": re},
	}
	return filter
}

// GetEnforcementEvents returns a tenant's enforcement activity, newest first.
func (m *MongoDB) GetEnforcementEvents(q EnforcementEventQuery) ([]*EnforcementEvent, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	filter := enforcementEventFilter(q)
	limit, skip := q.Limit, q.Skip

	total, err := m.EnforcementEvents.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	if limit <= 0 || limit > 500 {
		limit = 100
	}
	opts := options.Find().
		SetSort(bson.D{{Key: "at", Value: -1}, {Key: "_id", Value: -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))

	cur, err := m.EnforcementEvents.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = cur.Close(ctx) }()

	var out []*EnforcementEvent
	if err := cur.All(ctx, &out); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// DeleteEnforcementEventsByMachine removes a machine's enforcement history.
func (m *MongoDB) DeleteEnforcementEventsByMachine(machineID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := m.EnforcementEvents.DeleteMany(ctx, bson.M{"machine_id": machineID})
	return err
}

// CountEnforcementByMechanism totals a tenant's enforcement activity in a
// window, grouped by what was done.
//
// Counted from the enforcement events rather than the audit log because the
// decisions were made on endpoints: the audit log records what administrators
// did in the portal, and no administrator is present when a machine closes a
// blocked program at two in the morning.
func (m *MongoDB) CountEnforcementByMechanism(tenantID string, from, to time.Time) (map[EnforcementCount]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	match := bson.M{"tenant_id": tenantID, "at": bson.M{"$gte": from, "$lte": to}}
	// Grouped by outcome as well as mechanism.
	//
	// It used to group on mechanism alone, which meant the compliance report's
	// "elevation_grants" counted every elevate event whatever became of it.
	// Elevation is not implemented on any platform, so every one of those
	// events is a FAILURE — the endpoint saying it cannot honour the rule —
	// and the report therefore stated a count of privileges handed out that
	// was climbing every few minutes while the true figure was zero. A
	// compliance report asserting the opposite of the truth about privilege
	// grants is worse than no report.
	cur, err := m.EnforcementEvents.Aggregate(ctx, []bson.M{
		{"$match": match},
		{"$group": bson.M{
			"_id":   bson.M{"mechanism": "$mechanism", "outcome": "$outcome"},
			"count": bson.M{"$sum": 1},
		}},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(ctx) }()

	out := map[EnforcementCount]int64{}
	for cur.Next(ctx) {
		var row struct {
			ID    EnforcementCount `bson:"_id"`
			Count int64            `bson:"count"`
		}
		if err := cur.Decode(&row); err != nil {
			continue
		}
		out[row.ID] = row.Count
	}
	return out, cur.Err()
}

// ClaimNotification reserves the right to send one notification for key, and
// reports whether this caller won it.
//
// The claim is the INSERT. A unique _id makes it atomic, so two backends — or
// two reports from the same machine arriving together — cannot both be told to
// send. Whoever loses gets a duplicate-key error and stays quiet.
//
// Failing OPEN is deliberate. If the database cannot be reached, the caller is
// told to send: a duplicate alert is an annoyance, a missed one about
// administrator rights being granted is the thing this exists to report. The
// error is returned as well so the caller can log it.
func (m *MongoDB) ClaimNotification(key string, cooldown time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.NotificationClaims.InsertOne(ctx, bson.M{
		"_id":        key,
		"claimed_at": time.Now(),
		"expires_at": time.Now().Add(cooldown),
	})
	if err == nil {
		return true, nil
	}
	if mongo.IsDuplicateKeyError(err) {
		return false, nil
	}
	return true, err
}

// NotificationKey builds the identity of a notification for deduplication.
//
// Every part that distinguishes one alert from another belongs in it, and
// nothing else does. Including a timestamp or an event id would make every
// claim unique and silently disable the suppression; leaving out the
// application would collapse a whole machine's alerts into one and hide all
// but the first.
func NotificationKey(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			p = "-"
		}
		// The separator must not be forgeable from a part, or two different
		// alerts could claim the same key: an application literally named
		// "a|b" would otherwise collide with machine "a" plus application "b".
		p = strings.ReplaceAll(p, "|", "/")
		cleaned = append(cleaned, p)
	}
	return strings.Join(cleaned, "|")
}
