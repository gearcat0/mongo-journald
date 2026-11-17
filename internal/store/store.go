// Package store is the MongoDB write path: connect, ensure the TTL +
// lookup indexes, and an async batching sink. It mirrors the technique in
// the mover's internal/obs package.
package store

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Open connects (lazily) to Mongo and returns the target database. The
// driver connects in the background, so an unreachable server here is not
// fatal — the sink buffers then drops until it is reachable.
func Open(uri, dbName string) (*mongo.Database, error) {
	if uri == "" {
		return nil, fmt.Errorf("mongo uri is required")
	}
	if dbName == "" {
		dbName = "syslog"
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetAppName("mongo-journald").SetTimeout(30 * time.Second))
	if err != nil {
		return nil, err
	}
	return client.Database(dbName), nil
}

// EventIndexes are the lookup indexes for the journald events collection.
var EventIndexes = []bson.D{
	{{Key: "at", Value: -1}},
	{{Key: "server", Value: 1}, {Key: "at", Value: -1}},
	{{Key: "level", Value: 1}, {Key: "at", Value: -1}},
	{{Key: "unit", Value: 1}, {Key: "at", Value: -1}},
}

// EnsureIndexes creates the TTL index on expireAt (expireAfterSeconds 0: a
// document expires at its own expireAt; one without the field never does)
// plus the given lookup indexes. It is idempotent, so every host may call
// it at startup.
func EnsureIndexes(ctx context.Context, db *mongo.Database, coll string, keys ...bson.D) error {
	models := []mongo.IndexModel{
		{Keys: bson.D{{Key: "expireAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("expireAt_ttl")},
	}
	for _, k := range keys {
		models = append(models, mongo.IndexModel{Keys: k})
	}
	return createIndexes(ctx, db, coll, models)
}

// EnsureUnique creates a unique index (used by the hourly rollups, whose
// upserts key on it) alongside the TTL index.
func EnsureUnique(ctx context.Context, db *mongo.Database, coll string, keys bson.D) error {
	models := []mongo.IndexModel{
		{Keys: bson.D{{Key: "expireAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("expireAt_ttl")},
		{Keys: keys, Options: options.Index().SetUnique(true).SetName("rollup_key")},
	}
	return createIndexes(ctx, db, coll, models)
}

func createIndexes(ctx context.Context, db *mongo.Database, coll string, models []mongo.IndexModel) error {
	if _, err := db.Collection(coll).Indexes().CreateMany(ctx, models); err != nil {
		return fmt.Errorf("%s: %w", coll, err)
	}
	return nil
}
