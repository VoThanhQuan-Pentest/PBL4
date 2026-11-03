package main

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
)

// sourceIPPolicy is opt-in for an immediate proxy which replaces XFF with one
// numeric socket address. It is not a general client-supplied forwarding chain.
type sourceIPPolicy struct {
	trusted []netip.Prefix
}

func newSourceIPPolicy(raw string) (sourceIPPolicy, error) {
	var result sourceIPPolicy
	if strings.TrimSpace(raw) == "" {
		return result, nil
	}
	for _, value := range strings.Split(raw, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() ||
			prefix.Addr().Zone() != "" || prefix != prefix.Masked() ||
			prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return sourceIPPolicy{}, errors.New("trusted proxies require canonical numeric, non-universal CIDRs")
		}
		result.trusted = append(result.trusted, prefix)
	}
	return result, nil
}

func (policy sourceIPPolicy) resolvePublic(request *http.Request) (netip.Addr, error) {
	peer, err := directClientIP(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	trusted := false
	for _, prefix := range policy.trusted {
		if prefix.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		return peer, nil
	}
	values := request.Header.Values("X-Forwarded-For")
	if len(values) != 1 || len(values[0]) > 128 {
		return netip.Addr{}, errors.New("invalid trusted proxy forwarding header")
	}
	address, err := netip.ParseAddr(strings.Trim(values[0], " \t"))
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, errors.New("invalid trusted proxy forwarding header")
	}
	address = address.Unmap()
	if address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, errors.New("invalid trusted proxy forwarding address")
	}
	return address, nil
}
