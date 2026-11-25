package policy

import (
	"context"
	"math"
	"sync"
	"time"
)

// Limiter paces egress with two token buckets — campaign-global and
// per-host — plus random jitter between requests (README §6.3). Wait blocks
// until a slot is available or ctx is done: callers cannot bypass pacing by
// ignoring an error.
type Limiter struct {
	mu       sync.Mutex
	global   *bucket
	perHost  float64
	hosts    map[string]*bucket
	now      func() time.Time
	jitterFn func() time.Duration
}

type bucket struct {
	rate   float64 // tokens per second
	cap    float64
	tokens float64
	last   time.Time
}

func newBucket(rate float64, now time.Time) *bucket {
	cap := math.Max(1, rate)
	return &bucket{rate: rate, cap: cap, tokens: cap, last: now}
}

// NewLimiter builds a limiter from the scope's rate config. now and jitterFn
// are injectable for tests; jitterFn returns the delay to add after a slot
// is acquired (return 0 to disable).
func NewLimiter(rate RateConfig, now func() time.Time, jitterFn func() time.Duration) *Limiter {
	if now == nil {
		now = time.Now
	}
	if jitterFn == nil {
		jitter := time.Duration(rate.JitterMS) * time.Millisecond
		jitterFn = func() time.Duration { return 0 }
		if jitter > 0 {
			jitterFn = func() time.Duration {
				return time.Duration(randInt63n(int64(jitter)))
			}
		}
	}
	return &Limiter{
		global:   newBucket(rate.RequestsPerSecond, now()),
		perHost:  rate.PerHostPerSecond,
		hosts:    make(map[string]*bucket),
		now:      now,
		jitterFn: jitterFn,
	}
}

// Wait blocks until the request may proceed under both buckets, then adds
// jitter. Fails with ctx's error if pacing outlasts the context.
func (l *Limiter) Wait(ctx context.Context, hostKey string) error {
	for {
		now := l.now()
		l.mu.Lock()
		l.global.refillTo(now)
		hb := l.hosts[hostKey]
		if hb == nil {
			hb = newBucket(l.perHost, now)
			l.hosts[hostKey] = hb
		}
		hb.refillTo(now)
		wait := max(l.global.waitDuration(), hb.waitDuration())
		if wait == 0 {
			l.global.take()
			hb.take()
			l.mu.Unlock()
			break
		}
		l.mu.Unlock()
		if err := sleepCtx(ctx, wait); err != nil {
			return err
		}
	}
	if j := l.jitterFn(); j > 0 {
		if err := sleepCtx(ctx, j); err != nil {
			return err
		}
	}
	return nil
}

func (b *bucket) refillTo(now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	b.tokens = math.Min(b.cap, b.tokens+elapsed*b.rate)
	b.last = now
}

func (b *bucket) waitDuration() time.Duration {
	if b.tokens >= 1 {
		return 0
	}
	need := 1 - b.tokens
	return time.Duration(need / b.rate * float64(time.Second))
}

func (b *bucket) take() { b.tokens-- }

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
