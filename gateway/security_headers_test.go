package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func assertGatewaySecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for _, directive := range []string{"default-src 'none'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'none'"} {
		if !strings.Contains(header.Get("Content-Security-Policy"), directive) {
			t.Errorf("missing CSP directive %q", directive)
		}
	}
	if header.Get("X-Content-Type-Options") != "nosniff" || header.Get("X-Frame-Options") != "DENY" {
		t.Error("gateway-owned response is missing MIME/frame protection")
	}
	for _, key := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if len(header.Values(key)) != 1 {
			t.Errorf("expected one %s header", key)
		}
	}
}

func TestGatewayOwnedResponsesHaveSecurityHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, path, body  string
		management, ready bool
		status            int
	}{
		{"healthy JSON", "/healthz", "", false, true, http.StatusOK},
		{"policy unavailable", "/healthz", "Policy not ready\n", false, false, http.StatusServiceUnavailable},
		{"management route rejected", "/api/orders", "404 page not found\n", true, false, http.StatusNotFound},
		{"proxy unavailable", "/api/siem/status", "Upstream unavailable\n", true, false, http.StatusBadGateway},
		{"fixture method rejected", "/internal/v1/prevention/test", "Method not allowed\n", false, false, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway, err := newServer("http://127.0.0.1:1", "", "", io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if tc.ready {
				gateway.policy.Store(testPolicy(t, nil, nil))
			}
			request := httptest.NewRequest(http.MethodGet, "http://owned.test"+tc.path, nil)
			response := httptest.NewRecorder()
			if tc.management {
				gateway.ServeManagementHTTP(response, request)
			} else {
				gateway.ServeHTTP(response, request)
			}
			if response.Code != tc.status {
				t.Fatalf("status=%d expected=%d", response.Code, tc.status)
			}
			if tc.body != "" && response.Body.String() != tc.body {
				t.Fatal("existing error body changed")
			}
			if tc.ready && !strings.Contains(response.Body.String(), `"status":"UP"`) {
				t.Fatal("health response changed")
			}
			assertGatewaySecurityHeaders(t, response.Header())
		})
	}
}

func TestManagementProxyPreservesUpstreamPolicyCookieAndBody(t *testing.T) {
	const policy = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'self' https://owned.style.test"
	const body = `{"owned":"response"}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		http.SetCookie(w, &http.Cookie{Name: "owned_session", Value: "fixture", HttpOnly: true, Path: "/"})
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()
	gateway, err := newServer(upstream.URL, "", "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	gateway.ServeManagementHTTP(response, httptest.NewRequest(http.MethodGet, "http://owned.test/api/siem/status", nil))
	if response.Code != http.StatusUnauthorized || response.Body.String() != body {
		t.Fatal("upstream response changed")
	}
	if response.Header().Get("Content-Security-Policy") != policy || len(response.Header().Values("Content-Security-Policy")) != 1 {
		t.Fatal("upstream policy changed or duplicated")
	}
	if response.Header().Get("Cache-Control") != "no-store" || len(response.Result().Cookies()) != 1 || !response.Result().Cookies()[0].HttpOnly {
		t.Fatal("upstream cache/cookie changed")
	}
}
