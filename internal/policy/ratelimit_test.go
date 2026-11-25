package policy

import (
	"context"
	"testing"
	"time"
)

func TestBucketRefillAndTake(t *testing.T) {
	t0 := time.Unix(0, 0)
	b := newBucket(2, t0) // rate 2/s, capacity 2
	b.take()
	b.take()
	if b.waitDuration() == 0 {
		t.Fatal("an empty bucket must report a wait")
	}
	b.refillTo(t0.Add(500 * time.Millisecond)) // +1 token at 2/s
	if b.tokens < 0.99 || b.tokens > 1.01 {
		t.Fatalf("tokens = %v, want ~1", b.tokens)
	}
	if b.waitDuration() != 0 {
		t.Fatal("one refilled token must be immediately available")
	}
	b.take()
	if b.waitDuration() == 0 {
		t.Fatal("bucket must be empty again")
	}
}

func TestBucketCapsAtCapacity(t *testing.T) {
	t0 := time.Unix(0, 0)
	b := newBucket(10, t0)
	b.refillTo(t0.Add(time.Hour))
	if b.tokens != b.cap {
		t.Fatalf("tokens = %v, want capped at %v", b.tokens, b.cap)
	}
}

func TestLimiterRespectsContext(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(RateConfig{RequestsPerSecond: 1, PerHostPerSecond: 1, JitterMS: 0},
		func() time.Time { return now }, // frozen: waits never elapse
		func() time.Duration { return 0 })

	if err := l.Wait(context.Background(), "host-a"); err != nil {
		t.Fatalf("first slot must be immediate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx, "host-a"); err == nil {
		t.Fatal("second immediate request on the same host must pace and hit the context deadline")
	}
}

func TestLimiterHostsAreIndependent(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(RateConfig{RequestsPerSecond: 100, PerHostPerSecond: 1, JitterMS: 0},
		func() time.Time { return now }, func() time.Duration { return 0 })

	// Per-host budget exhausted for host-a…
	if err := l.Wait(context.Background(), "host-a"); err != nil {
		t.Fatal(err)
	}
	ctxA, cancelA := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancelA()
	if err := l.Wait(ctxA, "host-a"); err == nil {
		t.Fatal("host-a must pace")
	}
	// …but host-b has its own bucket.
	if err := l.Wait(context.Background(), "host-b"); err != nil {
		t.Fatalf("host-b must have its own budget: %v", err)
	}
}

func TestLimiterAppliesJitterAfterAcquire(t *testing.T) {
	now := time.Unix(0, 0)
	called := 0
	l := NewLimiter(RateConfig{RequestsPerSecond: 100, PerHostPerSecond: 100, JitterMS: 0},
		func() time.Time { return now },
		func() time.Duration { called++; return 0 })

	if err := l.Wait(context.Background(), "h"); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("jitter called %d times, want 1", called)
	}
}
