package main

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const banPrefix = "flare:prevention:ban:"

const signatureWindowScript = `
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[3])
redis.call('EXPIRE', KEYS[1], 120)
local count = redis.call('ZCARD', KEYS[1])
if count >= 3 then
  if redis.call('SET', KEYS[2], ARGV[1], 'EX', 900, 'NX') then
    return 1
  end
end
return 0
`

type banCacheEntry struct {
	blockedAt int64
	until     time.Time
}

type redisSignals struct {
	client *redis.Client
	mu     sync.Mutex
	cache  map[netip.Addr]banCacheEntry
}

func newRedisSignals() *redisSignals {
	address := os.Getenv("PREVENTION_REDIS_ADDR")
	password := os.Getenv("REDIS_PASSWORD")
	if address == "" || password == "" {
		return nil
	}
	return &redisSignals{client: redis.NewClient(&redis.Options{
		Addr: address, Password: password, DialTimeout: 100 * time.Millisecond,
		ReadTimeout: 100 * time.Millisecond, WriteTimeout: 100 * time.Millisecond,
		PoolSize: 8,
	}), cache: make(map[netip.Addr]banCacheEntry)}
}

func (s *redisSignals) blocked(ip netip.Addr, revokedAt, now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	cached, found := s.cache[ip]
	s.mu.Unlock()
	if found && now.Before(cached.until) {
		return cached.blockedAt > 0 && time.UnixMilli(cached.blockedAt).After(revokedAt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	value, err := s.client.Get(ctx, banPrefix+ip.String()).Int64()
	if err != nil {
		return false
	}
	s.mu.Lock()
	if len(s.cache) >= 10000 {
		s.cache = make(map[netip.Addr]banCacheEntry)
	}
	s.cache[ip] = banCacheEntry{blockedAt: value, until: now.Add(time.Second)}
	s.mu.Unlock()
	return value > 0 && time.UnixMilli(value).After(revokedAt)
}

func (s *redisSignals) signatureHit(event securityEvent) bool {
	if s == nil {
		return false
	}
	ip, err := netip.ParseAddr(event.IP)
	if err != nil {
		return false
	}
	now := event.OccurredAt.UnixMilli()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	result, err := s.client.Eval(ctx, signatureWindowScript,
		[]string{"flare:prevention:signature-count:" + ip.String(), banPrefix + ip.String()},
		now, event.ID, now-60000).Int()
	if err != nil {
		return false
	}
	if result == 1 {
		s.mu.Lock()
		delete(s.cache, ip)
		s.mu.Unlock()
	}
	return result == 1
}

func (s *redisSignals) close() error {
	if s == nil {
		return nil
	}
	return s.client.Close()
}

func (s *redisSignals) status() string {
	if s == nil {
		return "NOT_CONFIGURED"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := s.client.Ping(ctx).Err(); err != nil {
		return "DEGRADED"
	}
	return "UP"
}
