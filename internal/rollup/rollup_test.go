package rollup

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func TestAccumulateAndModel(t *testing.T) {
	r := New(nil, Config{Collection: "dns_hourly", Server: "h1", KeyFields: []string{"qname", "qtype", "rcode"}, Retention: 60 * 24 * time.Hour})
	t1 := time.Date(2026, 11, 16, 9, 15, 0, 0, time.UTC)
	r.Add(t1, []any{"github.com", "A", "NOERROR"}, map[string]int64{"n": 1})
	r.Add(t1.Add(30*time.Minute), []any{"github.com", "A", "NOERROR"}, map[string]int64{"n": 2})
	r.Add(t1.Add(50*time.Minute), []any{"github.com", "A", "NOERROR"}, map[string]int64{"n": 1}) // next hour
	r.Add(t1, []any{"github.com", "AAAA", "NOERROR"}, map[string]int64{"n": 1})
	r.Add(t1, []any{nil, "A", "NOERROR"}, map[string]int64{"n": 1})
	r.Add(t1, []any{"", "A", "NOERROR"}, map[string]int64{"n": 1}) // "" and nil are distinct keys

	acc := r.take()
	if len(acc) != 5 {
		t.Fatalf("got %d keys, want 5", len(acc))
	}
	var e *entry
	for _, x := range acc {
		if x.key[0] == "github.com" && x.key[1] == "A" && x.hour.Hour() == 9 {
			e = x
		}
	}
	if e == nil || e.inc["n"] != 3 {
		t.Fatalf("09:00 github.com A = %+v", e)
	}

	m := r.Model(e).(*mongo.UpdateOneModel)
	wantFilter := bson.D{{Key: "server", Value: "h1"}, {Key: "hour", Value: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)},
		{Key: "qname", Value: "github.com"}, {Key: "qtype", Value: "A"}, {Key: "rcode", Value: "NOERROR"}}
	if got, _ := bson.Marshal(m.Filter); string(got) != string(mustMarshal(t, wantFilter)) {
		t.Errorf("filter = %v", m.Filter)
	}
	wantUpdate := bson.D{{Key: "$inc", Value: bson.D{{Key: "n", Value: int64(3)}}},
		{Key: "$setOnInsert", Value: bson.D{{Key: "expireAt", Value: time.Date(2027, 1, 15, 9, 0, 0, 0, time.UTC)}}}}
	if got, _ := bson.Marshal(m.Update); string(got) != string(mustMarshal(t, wantUpdate)) {
		t.Errorf("update = %v", m.Update)
	}
	if m.Upsert == nil || !*m.Upsert {
		t.Error("must upsert")
	}
	if len(r.take()) != 0 {
		t.Error("take must reset")
	}
}

func TestIndexKeys(t *testing.T) {
	k := IndexKeys([]string{"qname", "qtype"})
	if len(k) != 4 || k[0].Key != "server" || k[1].Key != "hour" || k[3].Key != "qtype" {
		t.Errorf("keys = %v", k)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := bson.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAddMax(t *testing.T) {
	r := New(nil, Config{Collection: "unit_metrics_hourly", Server: "h1", KeyFields: []string{"unit"}})
	t1 := time.Date(2026, 11, 22, 9, 1, 0, 0, time.UTC)
	r.AddMax(t1, []any{"a.service"}, map[string]int64{"n": 1, "mem_sum": 50}, map[string]int64{"mem_max": 50})
	r.AddMax(t1.Add(time.Minute), []any{"a.service"}, map[string]int64{"n": 1, "mem_sum": 70}, map[string]int64{"mem_max": 70})
	r.AddMax(t1.Add(2*time.Minute), []any{"a.service"}, map[string]int64{"n": 1, "mem_sum": 60}, map[string]int64{"mem_max": 60})
	acc := r.take()
	if len(acc) != 1 {
		t.Fatalf("got %d keys", len(acc))
	}
	for _, e := range acc {
		if e.inc["n"] != 3 || e.inc["mem_sum"] != 180 || e.max["mem_max"] != 70 {
			t.Fatalf("entry: %+v", e)
		}
		m := r.Model(e).(*mongo.UpdateOneModel)
		want := bson.D{{Key: "$inc", Value: bson.D{{Key: "mem_sum", Value: int64(180)}, {Key: "n", Value: int64(3)}}},
			{Key: "$max", Value: bson.D{{Key: "mem_max", Value: int64(70)}}}}
		if got, _ := bson.Marshal(m.Update); string(got) != string(mustMarshal(t, want)) {
			t.Errorf("update = %v", m.Update)
		}
	}
}
