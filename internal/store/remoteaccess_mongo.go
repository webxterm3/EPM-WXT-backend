package store

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Remote-access policy storage.
//
// A separate collection, for the same reasons as application policy: scoping
// cannot be expressed in a single per-tenant document, and a whole-document
// $set loses an update when two admins save at once.

func (m *MongoDB) CreateRemoteAccessPolicy(p *RemoteAccessPolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Now()
	p.CreatedAt, p.UpdatedAt = now, now

	res, err := m.RemoteAccessPolicies.InsertOne(ctx, p)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("a policy named %q already exists", p.Name)
		}
		return err
	}
	if id, ok := res.InsertedID.(primitive.ObjectID); ok {
		p.ID = id
	}
	return nil
}

func (m *MongoDB) UpdateRemoteAccessPolicy(p *RemoteAccessPolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p.UpdatedAt = time.Now()

	// Scoped by tenant as well as id, so a crafted id from one tenant cannot
	// reach another's policy.
	res, err := m.RemoteAccessPolicies.UpdateOne(ctx,
		bson.M{"_id": p.ID, "tenant_id": p.TenantID},
		bson.M{"$set": bson.M{
			"name": p.Name, "description": p.Description, "enabled": p.Enabled,
			"scope": p.Scope, "priority": p.Priority,
			"allowed_roles": p.AllowedRoles, "allowed_group_ids": p.AllowedGroupIDs,
			"allow_attended": p.AllowAttended, "allow_unattended": p.AllowUnattended,
			"allow_terminal": p.AllowTerminal, "time_windows": p.TimeWindows,
			"require_consent": p.RequireConsent, "require_reason": p.RequireReason,
			"require_recording":   p.RequireRecording,
			"max_session_minutes": p.MaxSessionMinutes,
			"updated_at":          p.UpdatedAt, "updated_by": p.UpdatedBy,
		}})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("a policy named %q already exists", p.Name)
		}
		return err
	}
	if res.MatchedCount == 0 {
		return fmt.Errorf("policy not found")
	}
	return nil
}

func (m *MongoDB) DeleteRemoteAccessPolicy(tenantID string, id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := m.RemoteAccessPolicies.DeleteOne(ctx, bson.M{"_id": id, "tenant_id": tenantID})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return fmt.Errorf("policy not found")
	}
	return nil
}

func (m *MongoDB) GetRemoteAccessPolicyByID(tenantID string, id primitive.ObjectID) (*RemoteAccessPolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var p RemoteAccessPolicy
	err := m.RemoteAccessPolicies.FindOne(ctx, bson.M{"_id": id, "tenant_id": tenantID}).Decode(&p)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetRemoteAccessPoliciesByTenant returns every policy for a tenant.
//
// The evaluator filters and orders them itself, so that precedence is decided
// in one place wherever the policies came from.
func (m *MongoDB) GetRemoteAccessPoliciesByTenant(tenantID string) ([]*RemoteAccessPolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cursor, err := m.RemoteAccessPolicies.Find(ctx, bson.M{"tenant_id": tenantID},
		options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var policies []*RemoteAccessPolicy
	if err := cursor.All(ctx, &policies); err != nil {
		return nil, err
	}
	return policies, nil
}
