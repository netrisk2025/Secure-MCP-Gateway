package authguard

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

func TestRateLimitAndLockout(t *testing.T) {
	now := time.Now()
	g := New(Config{PerSourcePerMinute: 3, MaxFailures: 2, LockoutBase: time.Minute, LockoutMax: 4 * time.Minute, Now: func() time.Time { return now }})
	for i := 0; i < 3; i++ {
		if _, err := g.Check("1.2.3.4", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := g.Check("1.2.3.4", "admin"); !errors.Is(err, ErrRateLimited) || d <= 0 {
		t.Fatalf("rate limit: %v %v", d, err)
	}
	now = now.Add(time.Minute)
	g.Failure("1.2.3.4", "admin")
	g.Failure("1.2.3.4", "admin")
	if _, err := g.Check("1.2.3.4", "admin"); !errors.Is(err, ErrLocked) {
		t.Fatalf("not locked: %v", err)
	}
	// The account is locked from every source.
	if _, err := g.Check("5.6.7.8", "admin"); !errors.Is(err, ErrLocked) {
		t.Fatalf("account lock not global: %v", err)
	}
	// Backoff doubles: a third failure after the first lock locks for 2m.
	now = now.Add(61 * time.Second)
	if _, err := g.Check("5.6.7.8", "admin"); err != nil {
		t.Fatalf("lock did not expire: %v", err)
	}
	g.Failure("5.6.7.8", "admin")
	now = now.Add(90 * time.Second)
	if _, err := g.Check("9.9.9.9", "admin"); !errors.Is(err, ErrLocked) {
		t.Fatalf("backoff not doubled: %v", err)
	}
	g.Success("admin")
	if _, err := g.Check("9.9.9.9", "admin"); err != nil {
		t.Fatalf("success did not clear the account: %v", err)
	}
	// A source spraying different accounts is locked for every account.
	g.Failure("7.7.7.7", "u1")
	g.Failure("7.7.7.7", "u2")
	g.Success("u2")
	if _, err := g.Check("7.7.7.7", "u3"); !errors.Is(err, ErrLocked) {
		t.Fatalf("spraying source not locked: %v", err)
	}
}

func TestVerifyBoundedAndDummy(t *testing.T) {
	g := New(Config{VerifyConcurrency: 1, VerifyWait: 50 * time.Millisecond})
	h, _ := keys.HashPassword("pw-123456789012")
	if ok, err := g.Verify(context.Background(), h, "pw-123456789012"); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, _ := g.Verify(context.Background(), "", "anything"); ok {
		t.Fatal("unknown account matched")
	}
	// With the only slot held, a second verification gives up with ErrBusy.
	g.sem <- struct{}{}
	if _, err := g.Verify(context.Background(), h, "x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v", err)
	}
	<-g.sem
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.Verify(context.Background(), h, "x") }()
	}
	wg.Wait()
	if !EqualName("admin", "admin") || EqualName("admin", "admin2") {
		t.Fatal("EqualName")
	}
}

func TestPruneBoundsTables(t *testing.T) {
	now := time.Now()
	g := New(Config{MaxEntries: 10, Now: func() time.Time { return now }})
	for i := 0; i < 50; i++ {
		g.Check(string(rune('a'+i)), "x")
		now = now.Add(2 * time.Second)
	}
	now = now.Add(time.Hour)
	g.Prune()
	if len(g.rate) != 0 || len(g.failure) != 0 {
		t.Fatalf("tables not pruned: %d %d", len(g.rate), len(g.failure))
	}
}

// A caller rotating source addresses cannot grow the rate table past
// MaxEntries: new sources share one overflow limit while the table is full
// of live entries, and get their own again once old entries expire.
func TestSourceTableBounded(t *testing.T) {
	now := time.Now()
	g := New(Config{PerSourcePerMinute: 2, MaxEntries: 4, Now: func() time.Time { return now }})
	for i := range 4 {
		if _, err := g.Check(fmt.Sprintf("10.0.0.%d", i), "a"); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		if _, err := g.Check(fmt.Sprintf("10.0.1.%d", i), "a"); err != nil {
			t.Fatalf("overflow request %d: %v", i, err)
		}
	}
	if _, err := g.Check("10.0.2.1", "a"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third new source while full: err = %v, want the shared overflow limit", err)
	}
	if n := len(g.rate); n > 5 {
		t.Fatalf("rate table holds %d entries, want at most MaxEntries+1", n)
	}
	now = now.Add(2 * time.Minute)
	if _, err := g.Check("10.0.3.1", "a"); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if _, ok := g.rate["10.0.3.1"]; !ok {
		t.Fatal("after expiry a new source should get its own entry")
	}
}

// Hash shares Verify's concurrency bound.
func TestHashBounded(t *testing.T) {
	g := New(Config{VerifyConcurrency: 1, VerifyWait: 20 * time.Millisecond})
	h, err := g.Hash(context.Background(), "secret-value")
	if err != nil || !keys.VerifyPassword(h, "secret-value") {
		t.Fatalf("hash %q err %v", h, err)
	}
	g.sem <- struct{}{} // occupy the only slot
	if _, err := g.Hash(context.Background(), "x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("hash with no free slot: %v, want ErrBusy", err)
	}
	<-g.sem
}
