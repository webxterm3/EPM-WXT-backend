package store

import (
	"context"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Audit querying.
//
// These entries were written but never readable: the only accessor was
// GetAuditLogsOlderThan, which exists for the archiver. Everything the backend
// recorded — remote sessions, policy changes — went into the database and out
// of reach, which is the same as not recording it for anyone asking a
// compliance question.

// auditFilter builds the query. Every filter starts from tenant_id, because an
// audit trail that can leak across organisations is worse than none.
func auditFilter(q AuditQuery) bson.M {
	filter := bson.M{"tenant_id": q.TenantID}

	if len(q.Actions) > 0 {
		filter["action"] = bson.M{"$in": q.Actions}
	}
	if q.Actor != "" {
		filter["actor_name"] = q.Actor
	}
	if q.AgentID != "" {
		filter["agent_id"] = q.AgentID
	}
	if q.Status != "" {
		filter["status"] = q.Status
	}

	if !q.From.IsZero() || !q.To.IsZero() {
		window := bson.M{}
		if !q.From.IsZero() {
			window["$gte"] = q.From
		}
		if !q.To.IsZero() {
			window["$lte"] = q.To
		}
		filter["timestamp"] = window
	}

	if search := strings.TrimSpace(q.Search); search != "" {
		escaped := regexEscape(search)
		filter["$or"] = []bson.M{
			{"actor_name": bson.M{"$regex": escaped, "$options": "i"}},
			{"machine_name": bson.M{"$regex": escaped, "$options": "i"}},
			{"resource_id": bson.M{"$regex": escaped, "$options": "i"}},
			{"action": bson.M{"$regex": escaped, "$options": "i"}},
		}
	}
	return filter
}

// GetAuditLogs lists entries newest first.
func (m *MongoDB) GetAuditLogs(q AuditQuery) ([]*AuditLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}})
	if q.Limit > 0 {
		opts.SetLimit(int64(q.Limit))
	}
	if q.Skip > 0 {
		opts.SetSkip(int64(q.Skip))
	}

	cursor, err := m.AuditLogs.Find(ctx, auditFilter(q), opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

// CountAuditLogs counts entries matching a query.
func (m *MongoDB) CountAuditLogs(q AuditQuery) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return m.AuditLogs.CountDocuments(ctx, auditFilter(q))
}

// StreamAuditLogs walks every matching entry oldest first.
//
// A callback rather than a slice, because an export covers a quarter and a
// busy fleet produces hundreds of thousands of entries — materialising those
// to write a CSV is how a download takes the server down with it. Oldest first
// because a report reads forwards in time.
func (m *MongoDB) StreamAuditLogs(ctx context.Context, q AuditQuery, fn func(*AuditLog) error) error {
	cursor, err := m.AuditLogs.Find(ctx, auditFilter(q),
		options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}}))
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var entry AuditLog
		if err := cursor.Decode(&entry); err != nil {
			return err
		}
		if err := fn(&entry); err != nil {
			return err
		}
	}
	return cursor.Err()
}

// AuditActionCount is one action and how often it occurred.
type AuditActionCount struct {
	Action string `bson:"_id" json:"action"`
	Count  int64  `bson:"count" json:"count"`
}

// CountAuditByAction groups a window by action, for the compliance summary.
func (m *MongoDB) CountAuditByAction(q AuditQuery) ([]AuditActionCount, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cursor, err := m.AuditLogs.Aggregate(ctx, []bson.M{
		{"$match": auditFilter(q)},
		{"$group": bson.M{"_id": "$action", "count": bson.M{"$sum": 1}}},
		{"$sort": bson.M{"count": -1}},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var out []AuditActionCount
	if err := cursor.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AuditActorCount is one actor and how many entries they generated.
type AuditActorCount struct {
	Actor string `bson:"_id" json:"actor"`
	Count int64  `bson:"count" json:"count"`
}

// CountAuditByActor groups a window by who acted.
func (m *MongoDB) CountAuditByActor(q AuditQuery, limit int) ([]AuditActorCount, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if limit <= 0 {
		limit = 20
	}
	cursor, err := m.AuditLogs.Aggregate(ctx, []bson.M{
		{"$match": auditFilter(q)},
		{"$group": bson.M{"_id": "$actor_name", "count": bson.M{"$sum": 1}}},
		{"$sort": bson.M{"count": -1}},
		{"$limit": limit},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var out []AuditActorCount
	if err := cursor.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}
