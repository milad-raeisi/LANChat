package discoverysrv

import (
	"net/netip"
	"sync"
	"time"
)

// maxRateBuckets bounds the memory used by the rate limiter.
const maxRateBuckets = 65536

// rateLimiter is a token-bucket limiter keyed by source address. IPv6
// sources are grouped by /64 so that one host cannot evade the limit by
// rotating addresses within its prefix.
type rateLimiter struct {
	rate  float64 // tokens per second
	burst float64

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	return &rateLimiter{rate: rate, burst: float64(burst), buckets: map[netip.Addr]*bucket{}}
}

func rateKey(a netip.Addr) netip.Addr {
	a = a.Unmap().WithZone("")
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return a
}

// allow takes one token for src and reports whether the request may proceed.
func (l *rateLimiter) allow(src netip.Addr, now time.Time) bool {
	key := rateKey(src)
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxRateBuckets {
			l.sweepLocked(now)
			if len(l.buckets) >= maxRateBuckets {
				return false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep forgets buckets that have refilled completely; they are
// indistinguishable from new ones.
func (l *rateLimiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
}

func (l *rateLimiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
