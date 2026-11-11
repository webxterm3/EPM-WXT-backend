package store

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Fleet configuration storage.
//
// One document per tenant, in its own collection rather than as fields on
// TenantConfig: that document is written whole with $set, so adding the
// default account's sealed password to it would mean every unrelated settings
// save is one missed re-read away from wiping it.

// GetFleetConfig returns a tenant's fleet configuration.
//
// A tenant that has never configured anything gets the zero value, which has
// the default account disabled. That default is load-bearing: a tenant
// created before this existed, or one whose document fails to read, must not
// start creating accounts on machines.
func (m *MongoDB) GetFleetConfig(tenantID string) (*FleetConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cfg FleetConfig
	if err := m.FleetConfigs.FindOne(ctx, bson.M{"tenant_id": tenantID}).Decode(&cfg); err != nil {
		return &FleetConfig{TenantID: tenantID}, nil
	}
	cfg.DefaultUser.HasPassword = cfg.DefaultUser.Password != ""
	return &cfg, nil
}

// SaveFleetConfig writes a tenant's fleet configuration.
func (m *MongoDB) SaveFleetConfig(cfg *FleetConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg.UpdatedAt = time.Now()

	_, err := m.FleetConfigs.UpdateOne(ctx,
		bson.M{"tenant_id": cfg.TenantID},
		bson.M{
			// Named fields rather than $set of the whole struct, so a future
			// setting on this document is not zeroed by a caller that
			// predates it.
			"$set": bson.M{
				"default_user": cfg.DefaultUser,
				"updated_at":   cfg.UpdatedAt,
				"updated_by":   cfg.UpdatedBy,
			},
			"$setOnInsert": bson.M{"tenant_id": cfg.TenantID},
		},
		options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("saving the fleet configuration: %w", err)
	}
	return nil
}

// MarkDefaultUserApplied records the default account having been requested on
// one machine.
//
// Set once per machine. Without it every reconnect would re-send the request,
// and the endpoint would answer "an account named X already exists" into the
// audit trail on every reconnect of every machine.
func (m *MongoDB) MarkDefaultUserApplied(agentID string, at time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"agent_id": agentID},
		bson.M{"$set": bson.M{"default_user_applied_at": at}})
	return err
}
