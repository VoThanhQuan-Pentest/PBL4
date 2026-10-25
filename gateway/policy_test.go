package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPolicy(t *testing.T, signatures []signature, blocks []block) *activePolicy {
	t.Helper()
	payload, err := json.Marshal(policyPayload{Signatures: signatures, Blocks: blocks})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	active, err := compilePolicy(policyEnvelope{
		Version: 1, Checksum: hex.EncodeToString(sum[:]), PolicyJSON: string(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	return active
}

func TestGatewayBlocksApprovedPathBeforeUpstream(t *testing.T) {
	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamHits++
		writer.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	secret := "/.env"
	policy := testPolicy(t, []signature{{
		ID: "sig-12345678", Kind: "PATH_EXACT", MatchValue: &secret, Action: "BLOCK",
	}}, nil)
	var events bytes.Buffer
	gateway, err := newServer(upstream.URL, "", "", &events)
	if err != nil {
		t.Fatal(err)
	}
	gateway.policy.Store(policy)
	proxy := httptest.NewServer(gateway)
	defer proxy.Close()

	request, _ := http.NewRequest("GET", proxy.URL+"/.env?password=NeverLogThis", nil)
	request.Header.Set("Cookie", "session=NeverLogThis")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || upstreamHits != 0 {
		t.Fatalf("attack status=%d upstream=%d", response.StatusCode, upstreamHits)
	}
	if strings.Contains(events.String(), "NeverLogThis") {
		t.Fatal("gateway event leaked request data")
	}
	found := false
	for _, line := range bytes.Split(bytes.TrimSpace(events.Bytes()), []byte("\n")) {
		var event securityEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		if event.RuleID == "sig-12345678" && event.Action == "DENY" {
			found = true
		}
	}
	if !found {
		t.Fatal("approved signature decision missing from gateway events")
	}
	benign, err := http.Get(proxy.URL + "/product/123")
	if err != nil {
		t.Fatal(err)
	}
	benign.Body.Close()
	if benign.StatusCode != http.StatusOK || upstreamHits != 1 {
		t.Fatalf("benign status=%d upstream=%d", benign.StatusCode, upstreamHits)
	}
}

func TestGatewayIPBlockExpiresWithoutPolicyRefresh(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	gateway, err := newServer(upstream.URL, "", "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	gateway.policy.Store(testPolicy(t, nil, []block{{
		ID: "block-12345678", IP: "127.0.0.1", ExpiresAt: time.Now().Add(80 * time.Millisecond),
	}}))
	proxy := httptest.NewServer(gateway)
	defer proxy.Close()
	first, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusForbidden {
		t.Fatalf("first status=%d", first.StatusCode)
	}
	time.Sleep(120 * time.Millisecond)
	second, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("expired block status=%d", second.StatusCode)
	}
}

func TestPolicyRejectsUntrustedRuleText(t *testing.T) {
	injected := "/admin\"\nSecRuleEngine Off"
	payload, _ := json.Marshal(policyPayload{Signatures: []signature{{
		ID: "sig-12345678", Kind: "PATH_EXACT", MatchValue: &injected, Action: "BLOCK",
	}}})
	sum := sha256.Sum256(payload)
	_, err := compilePolicy(policyEnvelope{
		Version: 1, Checksum: hex.EncodeToString(sum[:]), PolicyJSON: string(payload),
	})
	if err == nil {
		t.Fatal("SecLang injection must be rejected")
	}
}

func TestGatewayBuiltInDetectors(t *testing.T) {
	tests := []struct {
		name, kind, target string
	}{
		{"sqli", "SQLI", "/api/products?q=1%27%20UNION%20SELECT%20password%20FROM%20users"},
		{"xss", "XSS", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"},
		{"traversal", "TRAVERSAL", "/%2e%2e%2f%2e%2e%2fetc/passwd"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(t, []signature{{
				ID: "sig-12345678", Kind: test.kind, Action: "BLOCK",
			}}, nil)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			gateway, err := newServer(upstream.URL, "", "", io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			gateway.policy.Store(policy)
			proxy := httptest.NewServer(gateway)
			defer proxy.Close()
			response, err := http.Get(proxy.URL + test.target)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("target %s returned HTTP %d", test.name, response.StatusCode)
			}
			benign, err := http.Get(proxy.URL + "/api/products?q=O%27Reilly")
			if err != nil {
				t.Fatal(err)
			}
			benign.Body.Close()
			if benign.StatusCode != http.StatusOK {
				t.Fatalf("benign request returned HTTP %d", benign.StatusCode)
			}
		})
	}
}

func TestPathSignatureScopesMethodAndPathPrefix(t *testing.T) {
	method := "POST"
	scope := "/api/products"
	prefix := "/api/"
	policy := testPolicy(t, []signature{{
		ID: "sig-12345678", Kind: "PATH_PREFIX", HTTPMethod: &method,
		PathPrefix: &prefix, MatchValue: &scope, Action: "BLOCK",
	}}, nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	gateway, err := newServer(upstream.URL, "", "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	gateway.policy.Store(policy)
	proxy := httptest.NewServer(gateway)
	defer proxy.Close()
	for _, sample := range []struct {
		method, path string
		want         int
	}{{"POST", "/api/products/shoes", http.StatusForbidden},
		{"GET", "/api/products/shoes", http.StatusOK},
		{"POST", "/products/shoes", http.StatusOK}} {
		request, _ := http.NewRequest(sample.method, proxy.URL+sample.path, nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != sample.want {
			t.Fatalf("%s %s returned %d, wanted %d", sample.method, sample.path,
				response.StatusCode, sample.want)
		}
	}
}

func TestScopedSQLiSignatureRequiresMatchingMethodPathAndPayload(t *testing.T) {
	method := "POST"
	scope := "/api/products"
	policy := testPolicy(t, []signature{{
		ID: "sig-12345678", Kind: "SQLI", HTTPMethod: &method,
		PathPrefix: &scope, Action: "BLOCK",
	}}, nil)
	for _, sample := range []struct {
		method, path, body string
		blocked            bool
	}{
		{"POST", "/api/products/search", "q=1%27+UNION+SELECT+password+FROM+users", true},
		{"POST", "/api/products/search", "q=plain", false},
		{"POST", "/api/orders", "q=1%27+UNION+SELECT+password+FROM+users", false},
		{"GET", "/api/products/search", "q=1%27+UNION+SELECT+password+FROM+users", false},
	} {
		request := httptest.NewRequest(sample.method, "http://flarefitness.site"+sample.path,
			strings.NewReader(sample.body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rule, status, err := policy.inspect(request, netip.MustParseAddr("203.0.113.55"),
			[]byte(sample.body))
		if err != nil {
			t.Fatal(err)
		}
		if sample.blocked != (rule == "sig-12345678" && status == http.StatusForbidden) {
			t.Fatalf("%s %s body=%q: rule=%q status=%d", sample.method, sample.path,
				sample.body, rule, status)
		}
	}
}

func TestCandidateFixtureEndpointRequiresServiceToken(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "service.token")
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	gateway, err := newServer("http://nginx:80", "", tokenPath, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(gateway)
	defer httpServer.Close()
	payload := `{"signature":{"id":"sig-12345678","kind":"SQLI","action":"BLOCK"},
		"fixtures":[
		{"http_method":"POST","request_path":"/api/products",
		 "request_body":"q=1%27+UNION+SELECT+password+FROM+users","expected_match":true},
		{"http_method":"POST","request_path":"/api/products",
		 "request_body":"q=O%27Reilly","expected_match":false}]}`
	url := httpServer.URL + "/internal/v1/prevention/test"
	unauthorized, _ := http.Post(url, "application/json", strings.NewReader(payload))
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized test returned %d", unauthorized.StatusCode)
	}
	request, _ := http.NewRequest("POST", url, strings.NewReader(payload))
	request.Header.Set("X-Flare-Service-Token", token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("candidate test returned %d", response.StatusCode)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil || !result.Passed {
		t.Fatalf("fixture test did not pass: %v", err)
	}
}

func TestManagementChannelKeepsRecoveryRoutesWhenClientIsBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	gateway, err := newServer(upstream.URL, "", "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	gateway.policy.Store(testPolicy(t, nil, []block{{
		ID: "block-12345678", IP: "127.0.0.1", ExpiresAt: time.Now().Add(time.Hour),
	}}))
	web := httptest.NewServer(gateway)
	defer web.Close()
	management := httptest.NewServer(http.HandlerFunc(gateway.ServeManagementHTTP))
	defer management.Close()
	blocked, _ := http.Get(web.URL + "/api/siem/status")
	blocked.Body.Close()
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("web status=%d", blocked.StatusCode)
	}
	allowed, _ := http.Get(management.URL + "/api/siem/status")
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("management status=%d", allowed.StatusCode)
	}
	disallowed, _ := http.Get(management.URL + "/api/orders")
	disallowed.Body.Close()
	if disallowed.StatusCode != http.StatusNotFound {
		t.Fatalf("orders status=%d", disallowed.StatusCode)
	}
}

func TestGatewayOverwritesClientControlledForwardingHeaders(t *testing.T) {
	var forwarded, realIP, trace string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		forwarded = request.Header.Get("X-Forwarded-For")
		realIP = request.Header.Get("X-Real-IP")
		trace = request.Header.Get("X-Request-ID")
		writer.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	gateway, err := newServer(upstream.URL, "", "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	gateway.policy.Store(testPolicy(t, nil, nil))
	proxy := httptest.NewServer(gateway)
	defer proxy.Close()
	request, _ := http.NewRequest("GET", proxy.URL+"/api/health", nil)
	request.Header.Set("X-Forwarded-For", "8.8.8.8")
	request.Header.Set("X-Real-IP", "8.8.8.8")
	request.Header.Set("X-Request-ID", "attacker-controlled")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if forwarded != "127.0.0.1" || realIP != "127.0.0.1" ||
		trace == "attacker-controlled" || len(trace) != 32 {
		t.Fatalf("forwarded=%q real=%q trace=%q", forwarded, realIP, trace)
	}
}

func TestUntilRevokedPolicySurvivesRestartAndExplicitRelease(t *testing.T) {
	payload := policyPayload{SchemaVersion: 2, Blocks: []block{{ID: "block-permanent-123", IP: "8.8.8.8", DurationType: "UNTIL_REVOKED"}}}
	encode := func(version int64, payload policyPayload) policyEnvelope {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		return policyEnvelope{Version: version, Checksum: hex.EncodeToString(sum[:]), PolicyJSON: string(data)}
	}
	envelope := encode(10, payload)
	active, err := compilePolicy(envelope)
	if err != nil {
		t.Fatal(err)
	}
	until, ok := active.blockedIP[netip.MustParseAddr("8.8.8.8")]
	if !ok || !until.IsZero() {
		t.Fatal("until-revoked block has an invented expiry")
	}
	cache := filepath.Join(t.TempDir(), "policy.json")
	original := &server{policyCache: cache}
	if err = original.savePolicy(envelope); err != nil {
		t.Fatal(err)
	}
	restarted := &server{policyCache: cache}
	if err = restarted.loadPolicy(); err != nil {
		t.Fatal(err)
	}
	if _, ok = restarted.policy.Load().blockedIP[netip.MustParseAddr("8.8.8.8")]; !ok {
		t.Fatal("restart lost block")
	}
	release := encode(11, policyPayload{SchemaVersion: 2, RevokedIPs: []ipRevocation{{ID: "block-permanent-123", IP: "8.8.8.8", RevokedAt: time.Now().UTC()}}})
	if err = restarted.savePolicy(release); err != nil {
		t.Fatal(err)
	}
	released := &server{policyCache: cache}
	if err = released.loadPolicy(); err != nil {
		t.Fatal(err)
	}
	if len(released.policy.Load().blockedIP) != 0 || len(released.policy.Load().revokedIP) != 1 {
		t.Fatal("release was not durable")
	}
	payload.SchemaVersion = 1
	if _, err = compilePolicy(encode(12, payload)); err == nil {
		t.Fatal("legacy schema accepted an unlimited block")
	}
	if err = os.WriteFile(cache, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = released.loadPolicy(); err == nil {
		t.Fatal("corrupt policy accepted")
	}
}
