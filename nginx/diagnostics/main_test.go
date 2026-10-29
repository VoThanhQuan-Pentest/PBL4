package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestNativeDiagnosticsNeverCopyFreeText(t *testing.T) {
	for _, sample := range []struct{ native, code string }{
		{`connect() failed (111: Connection refused) while connecting to upstream, request: "GET /api?token=SECRET HTTP/1.1", upstream: "http://app/api?token=SECRET", host: "SECRET", referrer: "https://x/?password=SECRET"`, "upstream_connect_failed"},
		{`upstream timed out while reading response header from upstream, request: "SECRET"`, "upstream_timeout"},
		{`open() "/SECRET" failed (2: No such file or directory)`, "file_open_failed"},
		{`upstream sent too big header while reading response header, upstream: "SECRET"`, "upstream_header_too_large"},
		{`client intended to send too large body: SECRET bytes`, "request_body_too_large"},
		{`limiting requests, excess: SECRET`, "request_rate_limited"},
		{`unknown diagnostic SECRET`, "unclassified_native_error"},
	} {
		t.Run(sample.code, func(t *testing.T) {
			d := classify([]byte("2026/10/29 00:00:00 [error] 12#12: *3 " + sample.native + "\n"))
			if d.Code != sample.code || d.Severity != "error" {
				t.Fatalf("unexpected classification: %+v", d)
			}
			b, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "SECRET") {
				t.Fatal("native data retained")
			}
		})
	}
}

func TestUntrustedAndOversizedLinesAreOpaque(t *testing.T) {
	input := "SECRET\n" + strings.Repeat("SECRET", maxLine) + "\n" +
		"2026/10/29 00:00:00 [warn] 12#12: limiting requests, SECRET\n" +
		"2026/10/29 00:00:00 [error] 12#12: connect() failed SECRET" // unterminated
	var got []diagnostic
	err := consume(strings.NewReader(input), func(d diagnostic) error { got = append(got, d); return nil })
	if err != nil || len(got) != 4 {
		t.Fatalf("got %d events, err=%v", len(got), err)
	}
	for i, code := range []string{"unclassified_native_error", "unclassified_native_error", "request_rate_limited", "unclassified_native_error"} {
		if got[i].Code != code {
			t.Fatalf("event%d: %+v", i, got[i])
		}
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("untrusted data retained")
	}
}

func TestDiagnosticDeliveryFailureIsNotIgnored(t *testing.T) {
	want := errors.New("owned write failure")
	if got := consume(strings.NewReader("owned\n"), func(diagnostic) error { return want }); !errors.Is(got, want) {
		t.Fatal(got)
	}
}
