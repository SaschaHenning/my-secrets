package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func newTestLog(t *testing.T) *Log {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.sqlite")
	l, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestWriteRead(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()

	detail, _ := json.Marshal(map[string]any{"kind": "ai", "pid": 1234})
	for i := 0; i < 5; i++ {
		_, err := l.Write(ctx, Entry{
			Action: ActionGet, SecretPath: "jasp/tok", Org: "jasp",
			ActorKind: ActorAI, ActorDetail: detail, Result: ResultOK, Reason: "ok",
		})
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	entries, err := l.Tail(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("want 5 entries, got %d", len(entries))
	}
	if entries[0].ActorKind != ActorAI {
		t.Errorf("actor_kind mismatch: %q", entries[0].ActorKind)
	}
}

func TestFilters(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	_, _ = l.Write(ctx, Entry{Action: ActionGet, SecretPath: "jasp/a", Org: "jasp", ActorKind: ActorAI, Result: ResultOK})
	_, _ = l.Write(ctx, Entry{Action: ActionGet, SecretPath: "jasp/b", Org: "jasp", ActorKind: ActorHuman, Result: ResultOK})
	_, _ = l.Write(ctx, Entry{Action: ActionGet, SecretPath: "private/x", Org: "private", ActorKind: ActorAI, Result: ResultDenied, Reason: "policy"})

	ai, err := l.Tail(ctx, Filter{Actor: ActorAI, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(ai) != 2 {
		t.Errorf("filter actor=ai: want 2 entries, got %d", len(ai))
	}
	denied := 0
	for _, e := range ai {
		if e.Result == ResultDenied {
			denied++
		}
	}
	if denied != 1 {
		t.Errorf("want 1 denied ai entry, got %d", denied)
	}
}

func TestAppendOnly(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	seq, err := l.Write(ctx, Entry{Action: ActionGet, ActorKind: ActorHuman, Result: ResultOK})
	if err != nil {
		t.Fatal(err)
	}
	// Try to update — should fail.
	_, err = l.db.ExecContext(ctx, `UPDATE audit_log SET action='tamper' WHERE seq=?`, seq)
	if err == nil {
		t.Fatal("expected UPDATE to fail on append-only table")
	}
	// Try to delete — should fail.
	_, err = l.db.ExecContext(ctx, `DELETE FROM audit_log WHERE seq=?`, seq)
	if err == nil {
		t.Fatal("expected DELETE to fail on append-only table")
	}
}

func TestVerifyContiguous(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _ = l.Write(ctx, Entry{Action: ActionGet, ActorKind: ActorAI, Result: ResultOK})
	}
	ok, miss, err := l.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(miss) != 0 {
		t.Errorf("expected no gaps, got missing=%v", miss)
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	ts := time.Now().UTC().Truncate(time.Millisecond)
	_, _ = l.Write(ctx, Entry{TS: ts, Action: ActionGet, ActorKind: ActorAI, Result: ResultOK})
	e, _ := l.Tail(ctx, Filter{Limit: 1})
	if len(e) != 1 {
		t.Fatalf("want 1 entry")
	}
	if !e[0].TS.Equal(ts) {
		t.Errorf("ts mismatch: got %v, want %v", e[0].TS, ts)
	}
}
