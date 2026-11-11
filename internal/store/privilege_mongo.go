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

// Least-privilege policy storage.
//
// Its own collection, alongside app_policies rather than inside it, because
// the two policies match different things — applications and accounts — and
// because a privilege policy that was accidentally loaded as an application
// policy would decode into a struct where DemoteAdmins does not exist and
// would therefore appear to be asking for nothing.

func (m *MongoDB) CreatePrivilegePolicy(p *PrivilegePolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Now()
	p.CreatedAt, p.UpdatedAt = now, now

	res, err := m.PrivilegePolicies.InsertOne(ctx, p)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("a privilege policy named %q already exists", p.Name)
		}
		return err
	}
	if id, ok := res.InsertedID.(primitive.ObjectID); ok {
		p.ID = id
	}
	return nil
}

func (m *MongoDB) UpdatePrivilegePolicy(p *PrivilegePolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p.UpdatedAt = time.Now()

	// Scoped by tenant as well as id, so a crafted id from one tenant cannot
	// reach another's policy.
	res, err := m.PrivilegePolicies.UpdateOne(ctx,
		bson.M{"_id": p.ID, "tenant_id": p.TenantID},
		bson.M{"$set": bson.M{
			"name":          p.Name,
			"description":   p.Description,
			"enabled":       p.Enabled,
			"scope":         p.Scope,
			"mode":          p.Mode,
			"priority":      p.Priority,
			"demote_admins": p.DemoteAdmins,
			"keep_admin":    p.KeepAdmin,
			"break_glass":   p.BreakGlass,
			"elevation":     p.Elevation,
			"updated_at":    p.UpdatedAt,
			"updated_by":    p.UpdatedBy,
		}})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("a privilege policy named %q already exists", p.Name)
		}
		return err
	}
	if res.MatchedCount == 0 {
		return fmt.Errorf("privilege policy not found")
	}
	return nil
}

func (m *MongoDB) DeletePrivilegePolicy(tenantID string, id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := m.PrivilegePolicies.DeleteOne(ctx, bson.M{"_id": id, "tenant_id": tenantID})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return fmt.Errorf("privilege policy not found")
	}
	return nil
}

func (m *MongoDB) GetPrivilegePolicyByID(tenantID string, id primitive.ObjectID) (*PrivilegePolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var p PrivilegePolicy
	err := m.PrivilegePolicies.FindOne(ctx, bson.M{"_id": id, "tenant_id": tenantID}).Decode(&p)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

// GetPrivilegePoliciesByTenant returns every privilege policy a tenant has.
//
// Ordered so the list reads the way the resolver decides: most specific
// first, then by priority. An operator comparing the screen with what a
// machine actually got should not have to reorder it in their head.
func (m *MongoDB) GetPrivilegePoliciesByTenant(tenantID string) ([]*PrivilegePolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cur, err := m.PrivilegePolicies.Find(ctx, bson.M{"tenant_id": tenantID},
		options.Find().SetSort(bson.D{
			{Key: "priority", Value: -1},
			{Key: "created_at", Value: 1},
		}))
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(ctx) }()

	var out []*PrivilegePolicy
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetPrivilegeSettings returns a tenant's least-privilege enforcement switch.
//
// A tenant that has never chosen gets the zero value, which is enforcement
// off. That default is load-bearing: a tenant created before this existed, or
// one whose settings document fails to read, must end up not stripping
// anybody's administrator rights.
func (m *MongoDB) GetPrivilegeSettings(tenantID string) (*PrivilegeSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var s PrivilegeSettings
	err := m.PrivilegeSettings.FindOne(ctx, bson.M{"tenant_id": tenantID}).Decode(&s)
	if err != nil {
		// Absent is the normal state, not a failure.
		return &PrivilegeSettings{TenantID: tenantID}, nil
	}
	return &s, nil
}

// SetPrivilegeEnforcement turns least-privilege enforcement on or off.
func (m *MongoDB) SetPrivilegeEnforcement(tenantID string, enabled bool, actor string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	_, err := m.PrivilegeSettings.UpdateOne(ctx,
		bson.M{"tenant_id": tenantID},
		bson.M{
			// Only the fields this call owns, spelled out rather than a $set
			// of the whole struct, so a future setting on this document is
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
