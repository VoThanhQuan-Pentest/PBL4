package main

import (
	"encoding/json"
	"net/http"
)

const gatewayOwnedCSP = "default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"

// Only gateway-generated responses use these writers. Proxied content keeps its
// upstream policy, cookies, body and streaming behavior.
func setGatewaySecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Content-Security-Policy", gatewayOwnedCSP)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
}

func writeGatewayError(writer http.ResponseWriter, message string, status int) {
	setGatewaySecurityHeaders(writer)
	http.Error(writer, message, status)
}

func writeGatewayJSON(writer http.ResponseWriter, value any) {
	setGatewaySecurityHeaders(writer)
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}
