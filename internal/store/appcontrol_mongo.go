package store

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

// GetEnforcementEvents returns a tenant's enforcement activity, newest first.
//
// agentID narrows it to one machine; empty means the whole fleet.
func (m *MongoDB) GetEnforcementEvents(tenantID, agentID string, limit, skip int) ([]*EnforcementEvent, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	filter := bson.M{"tenant_id": tenantID}
	if agentID != "" {
		filter["agent_id"] = agentID
	}

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
func (m *MongoDB) CountEnforcementByMechanism(tenantID string, from, to time.Time) (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	match := bson.M{"tenant_id": tenantID, "at": bson.M{"$gte": from, "$lte": to}}
	cur, err := m.EnforcementEvents.Aggregate(ctx, []bson.M{
		{"$match": match},
		{"$group": bson.M{"_id": "$mechanism", "count": bson.M{"$sum": 1}}},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(ctx) }()

	out := map[string]int64{}
	for cur.Next(ctx) {
		var row struct {
			ID    string `bson:"_id"`
			Count int64  `bson:"count"`
		}
		if err := cur.Decode(&row); err != nil {
			continue
		}
		out[row.ID] = row.Count
	}
	return out, cur.Err()
}
