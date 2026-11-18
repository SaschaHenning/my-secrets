package audit

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

// Readers now run in parallel processes (#124), each with its own handle on
// the same DB. Without a busy timeout SQLite answers SQLITE_BUSY at once and
// the caller drops the audit row.
func TestParallelWritersOnSeparateHandlesKeepEveryRow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.sqlite")
	const writers, perWriter = 8, 25
	logs := make([]*Log, writers)
	for index := range logs {
		log, err := Open(path)
		if err != nil {
			t.Fatalf("open handle %d: %v", index, err)
		}
		t.Cleanup(func() { _ = log.Close() })
		logs[index] = log
	}
	var wait sync.WaitGroup
	errs := make(chan error, writers*perWriter)
	for _, log := range logs {
		wait.Add(1)
		go func(log *Log) {
			defer wait.Done()
			for range perWriter {
				if _, err := log.Write(context.Background(), Entry{
					Action: ActionGet, SecretPath: "jasp/x", ActorKind: "ai", Result: ResultOK,
				}); err != nil {
					errs <- err
				}
			}
		}(log)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("parallel audit write failed: %v", err)
	}
	count, err := logs[0].Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != writers*perWriter {
		t.Fatalf("audit rows = %d, want %d", count, writers*perWriter)
	}
}

// The signed path reads the previous row hash and then inserts; without an
// immediate transaction a parallel commit in between fails the upgrade with
// SQLITE_BUSY_SNAPSHOT, which busy_timeout does not retry.
func TestParallelSignedWritersKeepEveryRowAndChain(t *testing.T) {
	t.Setenv(EnvSignMode, "1")
	keys, err := NewMemoryKeyStore()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.sqlite")
	const writers, perWriter = 6, 15
	logs := make([]*Log, writers)
	for index := range logs {
		log, err := OpenWithKeyStore(path, keys)
		if err != nil {
			t.Fatalf("open handle %d: %v", index, err)
		}
		t.Cleanup(func() { _ = log.Close() })
		logs[index] = log
	}
	var wait sync.WaitGroup
	errs := make(chan error, writers*perWriter)
	for _, log := range logs {
		wait.Add(1)
		go func(log *Log) {
			defer wait.Done()
			for range perWriter {
				if _, err := log.Write(context.Background(), Entry{
					Action: ActionGet, SecretPath: "jasp/x", ActorKind: "ai", Result: ResultOK,
				}); err != nil {
					errs <- err
				}
			}
		}(log)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("parallel signed audit write failed: %v", err)
	}
	count, err := logs[0].Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != writers*perWriter {
		t.Fatalf("audit rows = %d, want %d", count, writers*perWriter)
	}
	ok, missing, err := logs[0].Verify(context.Background())
	if err != nil || !ok {
		t.Fatalf("hash chain broken after parallel writes: ok=%v missing=%v err=%v", ok, missing, err)
	}
}
