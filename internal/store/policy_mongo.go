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

// Application-control policy storage.
//
// A separate collection rather than a field on TenantConfig: that document is
// written as a whole with $set, which forces every save to re-read and
// re-attach everything else on it and loses an update when two admins save at
// once. Policies also need scoping, which a single per-tenant document cannot
// express at all.

func (m *MongoDB) CreateAppPolicy(p *AppPolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Now()
	p.CreatedAt, p.UpdatedAt = now, now

	res, err := m.AppPolicies.InsertOne(ctx, p)
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

func (m *MongoDB) UpdateAppPolicy(p *AppPolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p.UpdatedAt = time.Now()

	// Scoped by tenant as well as id, so a crafted id from one tenant cannot
	// reach another's policy.
	res, err := m.AppPolicies.UpdateOne(ctx,
		bson.M{"_id": p.ID, "tenant_id": p.TenantID},
		bson.M{"$set": bson.M{
			"name": p.Name, "description": p.Description, "enabled": p.Enabled,
			"scope": p.Scope, "mode": p.Mode, "priority": p.Priority,
			"default_action": p.DefaultAction, "rules": p.Rules,
			"updated_at": p.UpdatedAt, "updated_by": p.UpdatedBy,
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

func (m *MongoDB) DeleteAppPolicy(tenantID string, id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := m.AppPolicies.DeleteOne(ctx, bson.M{"_id": id, "tenant_id": tenantID})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return fmt.Errorf("policy not found")
	}
	return nil
}

func (m *MongoDB) GetAppPolicyByID(tenantID string, id primitive.ObjectID) (*AppPolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var p AppPolicy
	err := m.AppPolicies.FindOne(ctx, bson.M{"_id": id, "tenant_id": tenantID}).Decode(&p)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetAppPoliciesByTenant returns every policy for a tenant, enabled or not.
//
// The resolver filters and orders them itself, because it must apply the same
// ordering whether it was handed a fresh query or a cached list.
func (m *MongoDB) GetAppPoliciesByTenant(tenantID string) ([]*AppPolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cursor, err := m.AppPolicies.Find(ctx, bson.M{"tenant_id": tenantID},
		options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var policies []*AppPolicy
	if err := cursor.All(ctx, &policies); err != nil {
		return nil, err
	}
	return policies, nil
}
