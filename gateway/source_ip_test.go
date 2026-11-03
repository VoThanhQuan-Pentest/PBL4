package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSourceIPPolicyDirectModeIgnoresAllForwardedHeaders(t *testing.T) {
	policy, err := newSourceIPPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	for _, values := range [][]string{nil, {"198.51.100.77"}, {"bad, chain"}, {"one", "two"}} {
		request := httptest.NewRequest("GET", "http://fixture.test/api/health", nil)
		request.RemoteAddr = "203.0.113.9:4321"
		request.Header["X-Forwarded-For"] = values
		actual, err := policy.resolvePublic(request)
		if err != nil || actual.String() != "203.0.113.9" {
			t.Fatalf("direct identity=%v err=%v", actual, err)
		}
	}
}

func TestSourceIPPolicyTrustDependsOnSocketPeerNotAForwardedProxyAddress(t *testing.T) {
	policy, err := newSourceIPPolicy("172.31.0.51/32")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://fixture.test/api/health", nil)
	request.RemoteAddr = "203.0.113.9:4321"
	request.Header.Set("X-Forwarded-For", "172.31.0.51")
	request.Header.Set("X-Real-IP", "172.31.0.51")
	actual, err := policy.resolvePublic(request)
	if err != nil || actual.String() != "203.0.113.9" {
		t.Fatalf("forged trust=%v err=%v", actual, err)
	}
}

func TestSourceIPPolicyTrustedSingleNumericAddressForms(t *testing.T) {
	policy, err := newSourceIPPolicy("172.31.0.51/32,2001:db8::51/128")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ peer, header, want string }{
		{"172.31.0.51:4321", "198.51.100.77", "198.51.100.77"},
		{"[::ffff:172.31.0.51]:4321", "::ffff:198.51.100.77", "198.51.100.77"},
		{"[2001:db8::51]:4321", "2001:db8::99", "2001:db8::99"},
		{"172.31.0.51:4321", " \t198.51.100.77\t ", "198.51.100.77"},
	} {
		request := httptest.NewRequest("GET", "http://fixture.test/api/health", nil)
		request.RemoteAddr = test.peer
		request.Header.Set("X-Forwarded-For", test.header)
		actual, err := policy.resolvePublic(request)
		if err != nil || actual.String() != test.want {
			t.Fatalf("numeric identity=%v want=%s err=%v", actual, test.want, err)
		}
	}
}

func TestSourceIPPolicyRejectsAmbiguousOrMalformedTrustedHeaders(t *testing.T) {
	policy, err := newSourceIPPolicy("172.31.0.51/32")
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]string{nil, {}, {""}, {" \t"}, {"198.51.100.77", "203.0.113.9"},
		{"198.51.100.77,203.0.113.9"}, {"hostname.invalid"}, {"198.51.100.77:443"},
		{"[2001:db8::99]:443"}, {"fe80::1%eth0"}, {"::ffff:198.51.100.77%eth0"},
		{"010.0.0.1"}, {"0.0.0.0"}, {"::"}, {"224.0.0.1"}, {"ff02::1"},
		{"\u00a0198.51.100.77"}, {strings.Repeat(" ", 129) + "198.51.100.77"}}
	for index, values := range cases {
		request := httptest.NewRequest("GET", "http://fixture.test/api/health", nil)
		request.RemoteAddr = "172.31.0.51:4321"
		request.Header["X-Forwarded-For"] = values
		if _, err := policy.resolvePublic(request); err == nil {
			t.Fatalf("accepted invalid header case %d", index)
		}
	}
}

func TestSourceIPPolicyRejectsInvalidOrUniversalTrustConfiguration(t *testing.T) {
	for _, raw := range []string{"0.0.0.0/0", "::/0", "localhost/32", "172.31.0.51", "172.31.0.51/24",
		"172.31.0.51/32,", "172.31.0.51/32,,127.0.0.1/32", "fe80::1%eth0/128", "::ffff:172.31.0.51/128",
		"0.0.0.0/32", "224.0.0.0/4"} {
		if _, err := newSourceIPPolicy(raw); err == nil {
			t.Fatalf("accepted invalid trust configuration %q", raw)
		}
	}
}

func TestSourceIPPolicyRejectsMalformedSocketPeer(t *testing.T) {
	policy, _ := newSourceIPPolicy("172.31.0.51/32")
	request := httptest.NewRequest("GET", "http://fixture.test/api/health", nil)
	request.RemoteAddr = "not-a-socket"
	request.Header.Set("X-Forwarded-For", "198.51.100.77")
	if _, err := policy.resolvePublic(request); err == nil {
		t.Fatal("accepted malformed socket peer")
	}
}
