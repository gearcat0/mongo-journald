// Package model holds the types that flow from the journald reader to the
// Mongo sink.
package model

// Doc is one log document as written to Mongo. Like the mover's obs
// package it is a plain map, so the map keys are the Mongo field names
// (no struct tags, default driver map encoding).
type Doc = map[string]any

// Record is a document together with the journald cursor it came from.
// The sink persists the cursor only after the record's batch is durably
// written, giving at-least-once delivery with resume across restarts.
type Record struct {
	Doc    Doc
	Cursor string
}
