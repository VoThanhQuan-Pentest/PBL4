package main

import (
	"errors"
	"net/http"
	"net/netip"
	"sync"

	"github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

var observerOnce sync.Once
var observer coraza.WAF
var observerError error

func crsObserver() (coraza.WAF, error) {
	observerOnce.Do(func() {
		observer, observerError = coraza.NewWAF(coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives("Include @coraza.conf-recommended\n" +
				"Include @crs-setup.conf.example\n" +
				"Include @owasp_crs/*.conf\n" +
				"SecRuleEngine DetectionOnly\n" +
				"SecAuditEngine Off\n").
			WithErrorCallback(func(types.MatchedRule) {}))
	})
	return observer, observerError
}

func observeCRS(waf coraza.WAF, request *http.Request, ip netip.Addr, body []byte) ([]int, error) {
	if waf == nil {
		return nil, errors.New("CRS observer unavailable")
	}
	tx := waf.NewTransaction()
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
	tx.ProcessRequestHeaders()
	if len(body) > 0 {
		if _, _, err := tx.WriteRequestBody(body); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		return nil, err
	}
	ids := make([]int, 0, 5)
	for _, item := range tx.MatchedRules() {
		id := item.Rule().ID()
		if id >= 900000 && id < 1000000 && len(ids) < 5 {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
