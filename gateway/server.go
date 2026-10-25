package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const maxBody = 1024 * 1024

type securityEvent struct {
	Provenance      string    `json:"provenance"`
	DestinationIP   string    `json:"destination_ip,omitempty"`
	DestinationPort int       `json:"destination_port,omitempty"`
	Observer        string    `json:"observer"`
	ID              string    `json:"id"`
	TraceID         string    `json:"trace_id"`
	IP              string    `json:"ip_address"`
	EventType       string    `json:"event_type"`
	RuleID          string    `json:"rule_id,omitempty"`
	PolicyVersion   int64     `json:"policy_version"`
	Action          string    `json:"action"`
	Count           int       `json:"count,omitempty"`
	OccurredAt      time.Time `json:"occurred_at"`
}

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
}

type rateSignalBucket struct {
	count int
}

func (l *rateLimiter) allow(key string, rate, burst float64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = make(map[string]bucket)
	}
	if len(l.buckets) > 50000 {
		for name, value := range l.buckets {
			if now.Sub(value.last) > 5*time.Minute {
				delete(l.buckets, name)
			}
		}
		if len(l.buckets) > 50000 {
			return false
		}
	}
	value, found := l.buckets[key]
	if !found {
		value = bucket{tokens: burst, last: now}
	}
	value.tokens += now.Sub(value.last).Seconds() * rate
	if value.tokens > burst {
		value.tokens = burst
	}
	value.last = now
	if value.tokens < 1 {
		l.buckets[key] = value
		return false
	}
	value.tokens--
	l.buckets[key] = value
	return true
}

type server struct {
	policy       atomic.Pointer[activePolicy]
	redis        *redisSignals
	crs          coraza.WAF
	proxy        *httputil.ReverseProxy
	limits       rateLimiter
	rateMu       sync.Mutex
	rateSignals  map[netip.Addr]int
	events       io.Writer
	eventsMu     sync.Mutex
	logger       *slog.Logger
	policyClient *http.Client
	policyURL    string
	tokenFile    string
	policyCache  string
}

func newServer(upstream, policyURL, tokenFile string, events io.Writer) (*server, error) {
	crs, err := crsObserver()
	if err != nil {
		return nil, fmt.Errorf("CRS observer cannot start: %w", err)
	}
	target, err := url.Parse(upstream)
	if err != nil || target.Scheme != "http" || target.Host == "" {
		return nil, errors.New("upstream must be an internal HTTP origin")
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Director = nil
	proxy.Rewrite = func(proxied *httputil.ProxyRequest) {
		proxied.SetURL(target)
		proxied.Out.Host = proxied.In.Host
		ip := proxied.In.Context().Value(clientIPKey{}).(netip.Addr)
		proxied.Out.Header.Del("Forwarded")
		proxied.Out.Header.Del("X-Forwarded-For")
		proxied.Out.Header.Del("X-Real-IP")
		proxied.Out.Header.Del("X-Request-ID")
		proxied.Out.Header.Set("X-Forwarded-For", ip.String())
		proxied.Out.Header.Set("X-Real-IP", ip.String())
		proxied.Out.Header.Set("X-Request-ID", proxied.In.Context().Value(traceIDKey{}).(string))
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(writer, "Upstream unavailable", http.StatusBadGateway)
	}
	return &server{
		proxy: proxy, crs: crs, redis: newRedisSignals(), rateSignals: make(map[netip.Addr]int),
		policyURL: policyURL, tokenFile: tokenFile,
		events: events, logger: slog.New(slog.NewJSONHandler(os.Stderr, nil)),
		policyClient: &http.Client{Timeout: 3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

type clientIPKey struct{}
type traceIDKey struct{}

func directClientIP(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return ip.Unmap(), nil
}

func randomID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("OS random source unavailable")
	}
	return hex.EncodeToString(value[:])
}

func (s *server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/internal/v1/prevention/test" {
		s.testCandidate(writer, request)
		return
	}
	if request.URL.Path == "/healthz" {
		policy := s.policy.Load()
		if policy == nil {
			http.Error(writer, "Policy not ready", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"status": "UP", "policy_version": policy.version,
			"active_signatures": policy.signatures, "redis_state": s.redis.status(),
			"policy_schema_version": 2, "durable_policy": s.policyCache != "",
		})
		return
	}
	policy := s.policy.Load()
	if policy == nil {
		http.Error(writer, "Policy not ready", http.StatusServiceUnavailable)
		return
	}
	ip, err := directClientIP(request.RemoteAddr)
	if err != nil {
		http.Error(writer, "Invalid connection", http.StatusBadRequest)
		return
	}
	trace := randomID()
	writer.Header().Set("X-Request-ID", trace)
	now := time.Now().UTC()
	if until, found := policy.blockedIP[ip]; found && (until.IsZero() || now.Before(until)) {
		s.emitRequest(request, securityEvent{ID: randomID(), TraceID: trace, IP: ip.String(),
			EventType: "IP_BLOCK", PolicyVersion: policy.version,
			Action: "DENY", OccurredAt: now})
		http.Error(writer, "Access denied", http.StatusForbidden)
		return
	}
	if s.redis.blocked(ip, policy.revokedIP[ip], now) {
		s.emitRequest(request, securityEvent{ID: randomID(), TraceID: trace, IP: ip.String(),
			EventType: "IP_BLOCK", PolicyVersion: policy.version,
			Action: "DENY", OccurredAt: now})
		http.Error(writer, "Access denied", http.StatusForbidden)
		return
	}
	if !s.limits.allow(ip.String()+":web", 100, 200, now) {
		s.noteRateLimit(ip)
		http.Error(writer, "Too many requests", http.StatusTooManyRequests)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/api/") &&
		!s.limits.allow(ip.String()+":api", 30, 60, now) {
		s.noteRateLimit(ip)
		http.Error(writer, "Too many requests", http.StatusTooManyRequests)
		return
	}
	if request.ContentLength > maxBody {
		http.Error(writer, "Request too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxBody+1))
	if err != nil {
		http.Error(writer, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(body) > maxBody {
		http.Error(writer, "Request too large", http.StatusRequestEntityTooLarge)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if rules, err := observeCRS(s.crs, request, ip, body); err != nil {
		s.logger.Warn("CRS observation failed", "exception_type", fmt.Sprintf("%T", err))
	} else {
		for _, id := range rules {
			s.emitRequest(request, securityEvent{ID: randomID(), TraceID: trace, IP: ip.String(),
				EventType: "CRS_SIGNAL", RuleID: fmt.Sprint(id), PolicyVersion: policy.version,
				Action: "OBSERVE", OccurredAt: now})
		}
	}
	if ruleID, status, err := policy.inspect(request, ip, body); err != nil {
		s.logger.Error("WAF inspection failed", "exception_type", fmt.Sprintf("%T", err))
		http.Error(writer, "Inspection unavailable", http.StatusServiceUnavailable)
		return
	} else if status != 0 {
		s.emitRequest(request, securityEvent{ID: randomID(), TraceID: trace, IP: ip.String(),
			EventType: "SIGNATURE_MATCH", RuleID: ruleID, PolicyVersion: policy.version,
			Action: "DENY", OccurredAt: now})
		http.Error(writer, "Access denied", status)
		return
	}
	request.Header.Del("Forwarded")
	request.Header.Del("X-Forwarded-For")
	request.Header.Del("X-Real-IP")
	request.Header.Del("X-Request-ID")
	s.proxy.ServeHTTP(writer, request.WithContext(context.WithValue(
		context.WithValue(request.Context(), clientIPKey{}, ip), traceIDKey{}, trace)))
}

func (s *server) noteRateLimit(ip netip.Addr) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if len(s.rateSignals) >= 10000 {
		if _, found := s.rateSignals[ip]; !found {
			return
		}
	}
	s.rateSignals[ip]++
}

func (s *server) flushRateLimits(now time.Time) {
	s.rateMu.Lock()
	pending := s.rateSignals
	s.rateSignals = make(map[netip.Addr]int)
	s.rateMu.Unlock()
	for ip, count := range pending {
		if count == 0 {
			continue
		}
		s.emit(securityEvent{ID: randomID(), TraceID: randomID(), IP: ip.String(),
			EventType: "RATE_LIMIT", PolicyVersion: s.policyVersion(),
			Action: "THROTTLE", Count: count, OccurredAt: now.UTC()})
	}
}

func (s *server) policyVersion() int64 {
	if current := s.policy.Load(); current != nil {
		return current.version
	}
	return 0
}

/** Loopback-host-published recovery channel; Spring still enforces SOC RBAC and CSRF. */
func (s *server) ServeManagementHTTP(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	allowed := path == "/api/auth/csrf" || path == "/api/auth/login" ||
		path == "/api/auth/logout" || path == "/api/health" ||
		strings.HasPrefix(path, "/api/siem/")
	if !allowed {
		http.NotFound(writer, request)
		return
	}
	ip, err := directClientIP(request.RemoteAddr)
	if err != nil {
		http.Error(writer, "Invalid connection", http.StatusBadRequest)
		return
	}
	if !s.limits.allow(ip.String()+":management", 20, 40, time.Now().UTC()) {
		http.Error(writer, "Too many requests", http.StatusTooManyRequests)
		return
	}
	if request.ContentLength > maxBody {
		http.Error(writer, "Request too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(writer, "Invalid request body", http.StatusRequestEntityTooLarge)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	trace := randomID()
	writer.Header().Set("X-Request-ID", trace)
	request.Header.Del("Forwarded")
	request.Header.Del("X-Forwarded-For")
	request.Header.Del("X-Real-IP")
	request.Header.Del("X-Request-ID")
	s.proxy.ServeHTTP(writer, request.WithContext(context.WithValue(
		context.WithValue(request.Context(), clientIPKey{}, ip), traceIDKey{}, trace)))
}

type fixture struct {
	HTTPMethod    string  `json:"http_method"`
	RequestPath   string  `json:"request_path"`
	RequestBody   *string `json:"request_body"`
	ExpectedMatch bool    `json:"expected_match"`
}

type testCandidateRequest struct {
	Signature signature `json:"signature"`
	Fixtures  []fixture `json:"fixtures"`
}

func (s *server) testCandidate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	expected, err := os.ReadFile(s.tokenFile)
	actual := []byte(request.Header.Get("X-Flare-Service-Token"))
	if err != nil || len(expected) < 32 || len(expected) > 257 ||
		subtle.ConstantTimeCompare(bytes.TrimSpace(expected), actual) != 1 {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return
	}
	var input testCandidateRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil ||
		len(input.Fixtures) < 2 || len(input.Fixtures) > 20 {
		http.Error(writer, "Invalid fixtures", http.StatusBadRequest)
		return
	}
	payload, err := json.Marshal(policyPayload{Signatures: []signature{input.Signature}, Blocks: []block{}})
	if err != nil {
		http.Error(writer, "Invalid signature", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(payload)
	candidate, err := compilePolicy(policyEnvelope{
		Version: 0, Checksum: hex.EncodeToString(sum[:]), PolicyJSON: string(payload),
	})
	if err != nil {
		http.Error(writer, "Invalid signature", http.StatusBadRequest)
		return
	}
	passed, positive, negative := 0, false, false
	for _, sample := range input.Fixtures {
		if !validMethod(sample.HTTPMethod) || !safePath.MatchString(sample.RequestPath) ||
			(sample.RequestBody != nil && len(*sample.RequestBody) > 256) {
			http.Error(writer, "Invalid synthetic fixture", http.StatusBadRequest)
			return
		}
		var body []byte
		if sample.RequestBody != nil {
			body = []byte(*sample.RequestBody)
		}
		probe := httptest.NewRequest(sample.HTTPMethod, "http://flarefitness.site"+sample.RequestPath,
			bytes.NewReader(body))
		probe.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rule, status, err := candidate.inspect(probe, netip.MustParseAddr("203.0.113.55"), body)
		if err != nil {
			http.Error(writer, "Fixture inspection unavailable", http.StatusServiceUnavailable)
			return
		}
		matched := rule == input.Signature.ID && status == http.StatusForbidden
		if matched == sample.ExpectedMatch {
			passed++
		}
		if sample.ExpectedMatch {
			positive = true
		} else {
			negative = true
		}
	}
	if !positive || !negative {
		http.Error(writer, "Positive and benign fixtures required", http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"passed": passed == len(input.Fixtures), "passed_cases": passed,
		"total_cases": len(input.Fixtures),
	})
}

func (policy *activePolicy) inspect(request *http.Request, ip netip.Addr, body []byte) (string, int, error) {
	tx := policy.waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection(ip.String(), 0, "", 0)
	tx.ProcessURI(request.URL.RequestURI(), request.Method, request.Proto)
	for name, values := range request.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}
	tx.AddRequestHeader("Host", request.Host)
	tx.SetServerName(request.Host)
	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return policy.matchedID(tx), interruption.Status, nil
	}
	if len(body) > 0 {
		if interruption, _, err := tx.WriteRequestBody(body); err != nil {
			return "", 0, err
		} else if interruption != nil {
			return policy.matchedID(tx), interruption.Status, nil
		}
	}
	if interruption, err := tx.ProcessRequestBody(); err != nil {
		return "", 0, err
	} else if interruption != nil {
		return policy.matchedID(tx), interruption.Status, nil
	}
	return "", 0, nil
}

func (policy *activePolicy) matchedID(tx types.Transaction) string {
	for _, matched := range tx.MatchedRules() {
		if id, ok := policy.ruleIDs[matched.Rule().ID()]; ok {
			return id
		}
	}
	return ""
}

func (s *server) emit(event securityEvent) {
	event.Provenance = "LIVE_GATEWAY"
	event.Observer = "gateway"
	s.eventsMu.Lock()
	if err := json.NewEncoder(s.events).Encode(event); err != nil {
		s.logger.Error("Prevention event output failed", "exception_type", fmt.Sprintf("%T", err))
	}
	s.eventsMu.Unlock()
	if event.EventType == "SIGNATURE_MATCH" && s.redis.signatureHit(event) {
		s.emit(securityEvent{ID: randomID(), TraceID: event.TraceID, IP: event.IP,
			EventType: "AUTO_BLOCK", RuleID: event.RuleID,
			PolicyVersion: event.PolicyVersion, Action: "DENY",
			OccurredAt: time.Now().UTC()})
	}
}

func (s *server) refresh(ctx context.Context) error {
	token, err := os.ReadFile(s.tokenFile)
	if err != nil || len(token) < 32 || len(token) > 256 {
		return errors.New("prevention service token unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, "GET", s.policyURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("X-Flare-Service-Token", strings.TrimSpace(string(token)))
	response, err := s.policyClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("policy API HTTP %d", response.StatusCode)
	}
	var envelope policyEnvelope
	if err := json.NewDecoder(io.LimitReader(response.Body, 600*1024)).Decode(&envelope); err != nil {
		return err
	}
	current := s.policy.Load()
	if current != nil {
		if envelope.Version < current.version {
			return errors.New("policy version regressed")
		}
		if envelope.Version == current.version {
			if envelope.Checksum != current.checksum {
				return errors.New("policy checksum changed without a new version")
			}
			return s.acknowledge(ctx, current.version, current.checksum, strings.TrimSpace(string(token)))
		}
	}
	next, err := compilePolicy(envelope)
	if err != nil {
		return err
	}
	if err := s.savePolicy(envelope); err != nil {
		return err
	}
	s.policy.Store(next)
	s.logger.Info("Prevention policy applied", "version", next.version, "signatures", next.signatures)
	return s.acknowledge(ctx, next.version, next.checksum, strings.TrimSpace(string(token)))
}

func (s *server) acknowledge(ctx context.Context, version int64, checksum, token string) error {
	body, err := json.Marshal(map[string]any{"version": version, "checksum": checksum})
	if err != nil {
		return err
	}
	url := strings.TrimSuffix(s.policyURL, "/policy") + "/ack"
	request, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("X-Flare-Service-Token", token)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.policyClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("policy acknowledgement HTTP %d", response.StatusCode)
	}
	return nil
}

func (s *server) poll(ctx context.Context) {
	for {
		if err := s.refresh(ctx); err != nil {
			s.logger.Warn("Policy refresh failed", "exception_type", fmt.Sprintf("%T", err))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// The checksum is verified by compilePolicy on load. ACK follows fsync + rename + directory fsync.
func (s *server) savePolicy(envelope policyEnvelope) error {
	if s.policyCache == "" {
		return nil
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.policyCache)
	file, err := os.CreateTemp(directory, ".policy-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, s.policyCache); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *server) loadPolicy() error {
	if s.policyCache == "" {
		return nil
	}
	data, err := os.ReadFile(s.policyCache)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) > 600*1024 {
		return errors.New("cached policy exceeds size limit")
	}
	var envelope policyEnvelope
	if err = json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	policy, err := compilePolicy(envelope)
	if err != nil {
		return err
	}
	s.policy.Store(policy)
	return nil
}

func (s *server) emitRequest(request *http.Request, event securityEvent) {
	if address, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if socket, err := netip.ParseAddrPort(address.String()); err == nil {
			event.DestinationIP = socket.Addr().String()
			event.DestinationPort = int(socket.Port())
		}
	}
	s.emit(event)
}
