package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Installed-application inventory storage.
//
// The shape to keep in mind: an agent reports a complete snapshot, split into
// chunks. Each chunk upserts its applications; the final chunk then marks
// everything the scan did not touch as gone. Nothing is ever deleted, because
// "what was uninstalled last week" is a question this exists to answer.

// UpsertInventoryChunk writes one chunk of a snapshot.
//
// Returns how many rows were created, how many existing ones changed, and
// which applications are new to this machine.
//
// The list of new ones matters: evaluating policy against the whole inventory
// on every scan would re-report the same findings twice a day forever, and an
// audit trail that repeats itself is one nobody reads. Only an application
// that has just appeared is news.
func (m *MongoDB) UpsertInventoryChunk(machine *Machine, scanID string, apps []InstalledApp, at time.Time) (added, updated int64, newApps []InstalledApp, err error) {
	if len(apps) == 0 {
		return 0, 0, nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	deduped := dedupeByAppKey(apps)
	models := make([]mongo.WriteModel, 0, len(deduped))
	for _, app := range deduped {
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.M{"agent_id": machine.AgentID, "app_key": app.AppKey}).
			SetUpdate(inventoryUpdate(machine, app, scanID, at)).
			SetUpsert(true))
	}

	// Unordered so one bad row cannot stop the rest of the chunk.
	res, err := m.InstalledApps.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
	if res != nil {
		added, updated = res.UpsertedCount, res.ModifiedCount

		// UpsertedIDs is keyed by the model's position, which is how an insert
		// is told apart from an update after the fact.
		for index := range res.UpsertedIDs {
			if int(index) < len(deduped) {
				newApps = append(newApps, deduped[index])
			}
		}
	}
	if err != nil {
		return added, updated, newApps, fmt.Errorf("writing inventory chunk: %w", err)
	}
	return added, updated, newApps, nil
}

// dedupeByAppKey collapses repeats within one chunk.
//
// An unordered bulk write with two models matching the same filter can race
// against its own upsert and fail on the unique index. The agent already
// de-duplicates, so this is belt-and-braces against a future collector that
// forgets to.
func dedupeByAppKey(apps []InstalledApp) []InstalledApp {
	seen := make(map[string]int, len(apps))
	out := make([]InstalledApp, 0, len(apps))
	for _, app := range apps {
		if i, dup := seen[app.AppKey]; dup {
			out[i] = app // last one wins; they describe the same thing
			continue
		}
		seen[app.AppKey] = len(out)
		out = append(out, app)
	}
	return out
}

// SweepRemovedApps marks everything the given scan did not report.
//
// Keyed on the scan marker rather than on a list of three hundred keys: the
// alternative is a query listing every application the machine still has,
// which is both enormous and slow.
//
// The caller must only run this after the FINAL chunk of a complete scan. A
// partial scan says nothing about what is missing, and treating it as if it
// did would make one crashed agent look like a wiped machine.
func (m *MongoDB) SweepRemovedApps(agentID, scanID string, at time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := m.InstalledApps.UpdateMany(ctx,
		bson.M{"agent_id": agentID, "present": true, "scan_id": bson.M{"$ne": scanID}},
		bson.M{"$set": bson.M{"present": false, "removed_at": at, "updated_at": at}})
	if err != nil {
		return 0, fmt.Errorf("sweeping removed applications: %w", err)
	}
	return res.ModifiedCount, nil
}

// inventoryUpdate builds the upsert document for one application.
//
// Extracted from UpsertInventoryChunk so it can be checked against
// inventoryFilter without a database. The two have to agree about which
// fields exist on a row, and when they silently disagreed — machine_id was
// filtered on but never written — every machine's Applications tab came back
// empty while the agent reported happily twice a day.
func inventoryUpdate(machine *Machine, app InstalledApp, scanID string, at time.Time) bson.M {
	// $set and $setOnInsert must not name the same field — Mongo rejects
	// the update outright if they do. first_seen belongs only to insert,
	// last_seen only to set.
	set := bson.M{
		// machine_id is $set, not $setOnInsert: a machine deleted and
		// re-enrolled against the same registration token gets the same
		// agent_id, so these rows survive and match again — but with the OLD
		// machine_id, which no longer exists.
		"machine_id":   machine.ID,
		"machine_name": machine.Name,
		"tenant_id":    machine.TenantID,
		"name":         app.Name,
		"name_lower":   strings.ToLower(app.Name),
		"version":      app.Version,
		"publisher":    app.Publisher,
		"install_path": app.InstallPath,
		"exe_path":     app.ExePath,
		"bundle_id":    app.BundleID,
		"source":       app.Source,
		"scope":        app.Scope,
		"os_user":      app.OSUser,
		"arch":         app.Arch,
		"last_seen":    at,
		"present":      true,
		"scan_id":      scanID,
		"updated_at":   at,
	}
	if app.Publisher != "" {
		set["publisher_lower"] = strings.ToLower(app.Publisher)
	}
	if app.InstalledAt != nil {
		set["installed_at"] = app.InstalledAt
	}

	return bson.M{
		"$set": set,
		"$setOnInsert": bson.M{
			"agent_id":   machine.AgentID,
			"app_key":    app.AppKey,
			"first_seen": at,
		},
		// A reinstall has to clear the tombstone, or the row stays marked as
		// removed while plainly being present.
		"$unset": bson.M{"removed_at": ""},
	}
}

// inventoryFilter builds the per-machine listing filter.
func inventoryFilter(machineID primitive.ObjectID, q InventoryQuery) bson.M {
	filter := bson.M{"machine_id": machineID}
	if !q.IncludeRemoved {
		filter["present"] = true
	}
	if q.Source != "" {
		filter["source"] = q.Source
	}
	if search := strings.TrimSpace(q.Search); search != "" {
		// Anchored and quoted: an unanchored regex cannot use the index, and
		// an unquoted one lets a search box become a query injection.
		filter["$or"] = []bson.M{
			{"name_lower": bson.M{"$regex": "^" + regexEscape(strings.ToLower(search))}},
			{"publisher_lower": bson.M{"$regex": regexEscape(strings.ToLower(search))}},
		}
	}
	return filter
}

// regexEscape neutralises regex metacharacters in user input.
func regexEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (m *MongoDB) GetInstalledAppsByMachine(machineID primitive.ObjectID, q InventoryQuery) ([]*InstalledApp, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "name_lower", Value: 1}})
	if q.Limit > 0 {
		opts.SetLimit(int64(q.Limit))
	}
	if q.Skip > 0 {
		opts.SetSkip(int64(q.Skip))
	}

	cursor, err := m.InstalledApps.Find(ctx, inventoryFilter(machineID, q), opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var apps []*InstalledApp
	if err := cursor.All(ctx, &apps); err != nil {
		return nil, err
	}
	return apps, nil
}

func (m *MongoDB) CountInstalledAppsByMachine(machineID primitive.ObjectID, q InventoryQuery) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return m.InstalledApps.CountDocuments(ctx, inventoryFilter(machineID, q))
}

// StreamInstalledAppsByTenant walks every present application in a tenant.
//
// A callback rather than a returned slice: a hundred machines is tens of
// thousands of rows, and policy simulation reads all of them. Materialising
// that into memory on every simulation is how a backend falls over.
func (m *MongoDB) StreamInstalledAppsByTenant(ctx context.Context, tenantID string, fn func(*InstalledApp) error) error {
	cursor, err := m.InstalledApps.Find(ctx, bson.M{"tenant_id": tenantID, "present": true})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var app InstalledApp
		if err := cursor.Decode(&app); err != nil {
			return err
		}
		if err := fn(&app); err != nil {
			return err
		}
	}
	return cursor.Err()
}

func (m *MongoDB) CreateInventoryScan(scan *InventoryScan) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := m.InventoryScans.InsertOne(ctx, scan)
	if err != nil {
		return err
	}
	if id, ok := res.InsertedID.(primitive.ObjectID); ok {
		scan.ID = id
	}
	return nil
}

// UpdateInventoryScan records a chunk's effect, and completion when the final
// chunk lands.
func (m *MongoDB) UpdateInventoryScan(agentID, scanID string, added, updated, removed int64, reported int, complete bool, at time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	update := bson.M{
		"$inc": bson.M{"added": added, "updated": updated, "reported": reported},
		"$set": bson.M{"removed": removed},
	}
	if complete {
		update["$set"] = bson.M{"removed": removed, "complete": true, "finished_at": at}
	}

	_, err := m.InventoryScans.UpdateOne(ctx,
		bson.M{"agent_id": agentID, "scan_id": scanID}, update)
	return err
}

func (m *MongoDB) GetLatestInventoryScan(agentID string) (*InventoryScan, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var scan InventoryScan
	err := m.InventoryScans.FindOne(ctx,
		bson.M{"agent_id": agentID, "complete": true},
		options.FindOne().SetSort(bson.D{{Key: "started_at", Value: -1}}),
	).Decode(&scan)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

// GetAppCatalog aggregates the fleet's distinct applications.
//
// This is a derived query rather than a maintained collection on purpose. An
// uninstall on one machine may or may not remove a catalog entry depending on
// the other ninety-nine, so every incremental update degenerates into a full
// recount — you would be maintaining a second source of truth to save latency
// that is not currently a problem.
//
// It is served by the {tenant_id, present, name_lower} index. If the fleet
// ever outgrows this, the upgrade is a $merge of this same pipeline into a
// materialised collection on a ticker; nothing above this function changes.
func (m *MongoDB) GetAppCatalog(tenantID string, q CatalogQuery) ([]CatalogEntry, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	match := bson.M{"tenant_id": tenantID, "present": true}
	if search := strings.TrimSpace(q.Search); search != "" {
		match["$or"] = []bson.M{
			{"name_lower": bson.M{"$regex": regexEscape(strings.ToLower(search))}},
			{"publisher_lower": bson.M{"$regex": regexEscape(strings.ToLower(search))}},
		}
	}

	group := bson.M{
		"_id":           bson.M{"n": "$name_lower", "p": "$publisher_lower"},
		"name":          bson.M{"$first": "$name"},
		"publisher":     bson.M{"$first": "$publisher"},
		"agents":        bson.M{"$addToSet": "$agent_id"},
		"versions":      bson.M{"$addToSet": "$version"},
		"install_count": bson.M{"$sum": 1},
		"sample_exe":    bson.M{"$first": "$exe_path"},
		"sample_bundle": bson.M{"$first": "$bundle_id"},
	}

	// version_count is taken from the full set BEFORE the slice, so the count
	// stays truthful while the payload stays bounded.
	project := bson.M{
		"_id":           0,
		"name":          1,
		"publisher":     1,
		"install_count": 1,
		"sample_exe":    1,
		"sample_bundle": 1,
		"machine_count": bson.M{"$size": "$agents"},
		"version_count": bson.M{"$size": "$versions"},
		"versions":      bson.M{"$slice": []any{"$versions", 20}},
	}

	countPipeline := mongo.Pipeline{
		{{Key: "$match", Value: match}},
		{{Key: "$group", Value: bson.M{"_id": bson.M{"n": "$name_lower", "p": "$publisher_lower"}}}},
		{{Key: "$count", Value: "total"}},
	}
	total, err := m.aggregateCount(ctx, countPipeline)
	if err != nil {
		return nil, 0, err
	}

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: match}},
		{{Key: "$group", Value: group}},
		{{Key: "$project", Value: project}},
		{{Key: "$sort", Value: bson.D{{Key: "machine_count", Value: -1}, {Key: "name", Value: 1}}}},
	}
	if q.Skip > 0 {
		pipeline = append(pipeline, bson.D{{Key: "$skip", Value: q.Skip}})
	}
	if q.Limit > 0 {
		pipeline = append(pipeline, bson.D{{Key: "$limit", Value: q.Limit}})
	}

	// Deliberately NOT allowDiskUse: this should fail loudly when the fleet
	// outgrows an in-memory aggregation, rather than quietly becoming slow.
	cursor, err := m.InstalledApps.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, 0, fmt.Errorf("aggregating the application catalog: %w", err)
	}
	defer cursor.Close(ctx)

	var entries []CatalogEntry
	if err := cursor.All(ctx, &entries); err != nil {
		return nil, 0, err
	}
	return entries, total, nil
}

func (m *MongoDB) aggregateCount(ctx context.Context, pipeline mongo.Pipeline) (int64, error) {
	cursor, err := m.InstalledApps.Aggregate(ctx, pipeline)
	if err != nil {
		return 0, err
	}
	defer cursor.Close(ctx)

	var rows []struct {
		Total int64 `bson:"total"`
	}
	if err := cursor.All(ctx, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Total, nil
}

// GetMachinesWithApp lists the machines carrying one catalog entry.
func (m *MongoDB) GetMachinesWithApp(tenantID, name, publisher string, limit, skip int) ([]*InstalledApp, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	filter := bson.M{
		"tenant_id":  tenantID,
		"present":    true,
		"name_lower": strings.ToLower(strings.TrimSpace(name)),
	}
	if publisher != "" {
		filter["publisher_lower"] = strings.ToLower(strings.TrimSpace(publisher))
	}

	total, err := m.InstalledApps.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	opts := options.Find().SetSort(bson.D{{Key: "machine_name", Value: 1}})
	if limit > 0 {
		opts.SetLimit(int64(limit))
	}
	if skip > 0 {
		opts.SetSkip(int64(skip))
	}

	cursor, err := m.InstalledApps.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var apps []*InstalledApp
	if err := cursor.All(ctx, &apps); err != nil {
		return nil, 0, err
	}
	return apps, total, nil
}

// GetInventoryCoverage reports how much of the fleet has actually reported.
//
// Every number derived from the inventory is only as honest as this. A
// catalog count or a policy simulation presented without it invites the reader
// to believe it covers the whole fleet when it may cover two thirds of it.
func (m *MongoDB) GetInventoryCoverage(tenantID string, staleAfter time.Duration) (InventoryCoverage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var out InventoryCoverage

	machines, err := m.Machines.CountDocuments(ctx, bson.M{"tenant_id": tenantID})
	if err != nil {
		return out, err
	}
	out.MachinesTotal = int(machines)

	cursor, err := m.InventoryScans.Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"tenant_id": tenantID, "complete": true}}},
		{{Key: "$group", Value: bson.M{"_id": "$agent_id", "last": bson.M{"$max": "$started_at"}}}},
	})
	if err != nil {
		return out, err
	}
	defer cursor.Close(ctx)

	cutoff := time.Now().Add(-staleAfter)
	for cursor.Next(ctx) {
		var row struct {
			Last time.Time `bson:"last"`
		}
		if err := cursor.Decode(&row); err != nil {
			return out, err
		}
		out.MachinesReported++
		if row.Last.Before(cutoff) {
			out.MachinesStale++
		}
		if out.OldestReportAt.IsZero() || row.Last.Before(out.OldestReportAt) {
			out.OldestReportAt = row.Last
		}
	}
	return out, cursor.Err()
}
