package main

import (
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestRedisCreatesBanAfterThreeSignatureHits(t *testing.T) {
	if os.Getenv("PREVENTION_REDIS_TEST") != "yes" {
		t.Skip("requires the local isolated Redis service")
	}
	store := newRedisSignals()
	if store == nil {
		t.Fatal("Redis test requested but Redis is not configured")
	}
	defer store.close()
	ip := "198.51.100.77"
	now := time.Now().UTC()
	event := securityEvent{IP: ip, RuleID: "sig-test-12345678", TraceID: randomID(), OccurredAt: now}
	address := "flare:prevention:ban:" + ip
	counter := "flare:prevention:signature-count:" + ip
	defer store.client.Del(t.Context(), address, counter)
	for index := 0; index < 3; index++ {
		event.ID = randomID()
		event.OccurredAt = now.Add(time.Duration(index) * time.Second)
		banned := store.signatureHit(event)
		if banned != (index == 2) {
			t.Fatalf("hit %d ban=%v", index+1, banned)
		}
	}
	addressValue := netip.MustParseAddr(ip)
	if !store.blocked(addressValue, now, now.Add(4*time.Second)) {
		t.Fatal("third hit did not create an active ban")
	}
	if store.blocked(addressValue, now.Add(3*time.Second), now.Add(4*time.Second)) {
		t.Fatal("a ban created before a later manual unban remained active")
	}
	if !store.blocked(addressValue, now.Add(time.Second), now.Add(4*time.Second)) {
		t.Fatal("a newer Redis ban was hidden by an older unban")
	}
}
