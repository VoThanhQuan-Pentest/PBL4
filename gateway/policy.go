package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type signature struct {
	ID         string  `json:"id"`
	Kind       string  `json:"kind"`
	HTTPMethod *string `json:"http_method"`
	PathPrefix *string `json:"path_prefix"`
	MatchValue *string `json:"match_value"`
	Action     string  `json:"action"`
}

type block struct {
	DurationType string    `json:"duration_type,omitempty"`
	ID           string    `json:"id"`
	IP           string    `json:"ip_address"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type ipRevocation struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip_address"`
	RevokedAt time.Time `json:"revoked_at"`
}

type policyPayload struct {
	SchemaVersion int            `json:"schema_version,omitempty"`
	Signatures    []signature    `json:"signatures"`
	Blocks        []block        `json:"blocks"`
	RevokedIPs    []ipRevocation `json:"revoked_ips"`
}

type policyEnvelope struct {
	Version    int64  `json:"version"`
	Checksum   string `json:"checksum"`
	PolicyJSON string `json:"policy_json"`
}

type activePolicy struct {
	version     int64
	checksum    string
	waf         coraza.WAF
	ruleIDs     map[int]string
	blockedIP   map[netip.Addr]time.Time
	revokedIP   map[netip.Addr]time.Time
	signatures  int
	lastApplied time.Time
}

var safePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,159}$`)
var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func compilePolicy(envelope policyEnvelope) (*activePolicy, error) {
	if envelope.Version < 0 || len(envelope.PolicyJSON) > 512*1024 {
		return nil, errors.New("invalid policy version or size")
	}
	sum := sha256.Sum256([]byte(envelope.PolicyJSON))
	if envelope.Checksum != hex.EncodeToString(sum[:]) {
		return nil, errors.New("policy checksum mismatch")
	}
	var payload policyPayload
	if err := json.Unmarshal([]byte(envelope.PolicyJSON), &payload); err != nil {
		return nil, fmt.Errorf("invalid policy JSON: %w", err)
	}
	if payload.SchemaVersion > 2 || payload.SchemaVersion < 0 {
		return nil, errors.New("unsupported policy schema")
	}
	if len(payload.Signatures) > 1000 || len(payload.Blocks) > 5000 || len(payload.RevokedIPs) > 5000 {
		return nil, errors.New("policy exceeds bounded signature or block count")
	}
	sort.Slice(payload.Signatures, func(i, j int) bool {
		return payload.Signatures[i].ID < payload.Signatures[j].ID
	})
	directives := []string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecRequestBodyLimit 1048576",
		"SecRequestBodyLimitAction Reject",
		"SecResponseBodyAccess Off",
		"SecAuditEngine Off",
	}
	ruleIDs := make(map[int]string, len(payload.Signatures))
	for index, item := range payload.Signatures {
		if !safeIdentifier.MatchString(item.ID) || item.Action != "BLOCK" {
			return nil, errors.New("invalid signature ID or action")
		}
		if item.HTTPMethod != nil && !validMethod(*item.HTTPMethod) {
			return nil, errors.New("invalid signature method")
		}
		if item.PathPrefix != nil && !safePath.MatchString(*item.PathPrefix) {
			return nil, errors.New("invalid signature path scope")
		}
		ruleID := 1001000 + index
		ruleIDs[ruleID] = item.ID
		var variable, operator, phase string
		switch item.Kind {
		case "PATH_EXACT":
			if item.MatchValue == nil || !safePath.MatchString(*item.MatchValue) {
				return nil, errors.New("invalid literal path")
			}
			variable, phase = "REQUEST_FILENAME", "1"
			operator = "@streq " + *item.MatchValue
		case "PATH_PREFIX":
			if item.MatchValue == nil || !safePath.MatchString(*item.MatchValue) {
				return nil, errors.New("invalid literal path")
			}
			variable, phase = "REQUEST_FILENAME", "1"
			operator = "@beginsWith " + *item.MatchValue
		case "SQLI":
			if item.MatchValue != nil {
				return nil, errors.New("detector cannot have rule text")
			}
			variable, operator, phase = "ARGS|REQUEST_BODY", "@detectSQLi", "2"
		case "XSS":
			if item.MatchValue != nil {
				return nil, errors.New("detector cannot have rule text")
			}
			variable, operator, phase = "ARGS|REQUEST_BODY", "@detectXSS", "2"
		case "TRAVERSAL":
			if item.MatchValue != nil {
				return nil, errors.New("detector cannot have rule text")
			}
			variable, operator, phase = "REQUEST_URI_RAW",
				"@rx (?i)(?:\\.\\.|%2e%2e|%252e%252e)(?:/|%2f|%5c)", "1"
		default:
			return nil, errors.New("unsupported signature kind")
		}
		type condition struct{ variable, operator string }
		conditions := []condition{{variable, operator}}
		if item.HTTPMethod != nil {
			conditions = append(conditions, condition{"REQUEST_METHOD", "@streq " + *item.HTTPMethod})
		}
		if item.PathPrefix != nil {
			conditions = append(conditions, condition{"REQUEST_FILENAME", "@beginsWith " + *item.PathPrefix})
		}
		for step, test := range conditions {
			actions := "t:none"
			if step == 0 {
				actions = fmt.Sprintf("id:%d,phase:%s,deny,status:403,nolog,t:none", ruleID, phase)
			}
			if step+1 < len(conditions) {
				actions += ",chain"
			}
			directives = append(directives, fmt.Sprintf(
				"SecRule %s \"%s\" \"%s\"", test.variable, test.operator, actions))
		}
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(strings.Join(directives, "\n")).
		WithErrorCallback(func(types.MatchedRule) {}))
	if err != nil {
		return nil, fmt.Errorf("cannot compile prevention rules: %w", err)
	}
	blocked := make(map[netip.Addr]time.Time, len(payload.Blocks))
	for _, item := range payload.Blocks {
		if !safeIdentifier.MatchString(item.ID) ||
			(item.DurationType == "UNTIL_REVOKED" && (payload.SchemaVersion < 2 || !item.ExpiresAt.IsZero())) ||
			(item.DurationType != "UNTIL_REVOKED" && (item.ExpiresAt.IsZero() || (item.DurationType != "" && item.DurationType != "TEMPORARY"))) {
			return nil, errors.New("invalid IP block")
		}
		ip, err := netip.ParseAddr(item.IP)
		if err != nil {
			return nil, errors.New("invalid blocked IP")
		}
		blocked[ip.Unmap()] = item.ExpiresAt
	}
	revoked := make(map[netip.Addr]time.Time, len(payload.RevokedIPs))
	for _, item := range payload.RevokedIPs {
		if !safeIdentifier.MatchString(item.ID) || item.RevokedAt.IsZero() {
			return nil, errors.New("invalid IP revocation")
		}
		ip, err := netip.ParseAddr(item.IP)
		if err != nil {
			return nil, errors.New("invalid revoked IP")
		}
		ip = ip.Unmap()
		if item.RevokedAt.After(revoked[ip]) {
			revoked[ip] = item.RevokedAt
		}
	}
	return &activePolicy{
		version: envelope.Version, checksum: envelope.Checksum,
		waf: waf, ruleIDs: ruleIDs, blockedIP: blocked, revokedIP: revoked,
		signatures: len(payload.Signatures), lastApplied: time.Now().UTC(),
	}, nil
}

func validMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}
