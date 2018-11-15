// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"net/http"
	"strings"
	"net"
	"encoding/json"
	"github.com/httprouter"
	"github.com/satori/go.uuid"
	"vesper/stats"
)

// getClientIP returns client's real public IP address from http request headers.
func getClientIP(r *http.Request) string {
	// Fetch header value
	xRealIP := r.Header.Get("X-Real-Ip")
	xForwardedFor := r.Header.Get("X-Forwarded-For")

	// If both are empty, lookip IP from remote address
	if xRealIP == "" && xForwardedFor == "" {
		var remoteIP string

		// If colon in remote address, remove the port number
		// otherwise, return remote address as is
		if strings.ContainsRune(r.RemoteAddr, ':') {
			remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		} else {
			remoteIP = r.RemoteAddr
		}
		return remoteIP
	}
	// Check list of IPs in X-Forwarded-For and return the first address
	for _, address := range strings.Split(xForwardedFor, ",") {
		address = strings.TrimSpace(address)
		return address
	}
	// If not X-Forwarded-For or RemoteAddr, return X-Real-IP
	return xRealIP
}

// Retrieves all stats
func getStats(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	response.Header().Set("Access-Control-Allow-Origin", "*")
	response.Header().Set("Content-Type", "application/json")
	traceID := request.Header.Get("Trace-Id")
	if traceID == "" {
		traceID = "VESPER-" + uuid.NewV1().String()
	}
	response.Header().Set("Trace-Id", traceID)
	response.WriteHeader(http.StatusOK)
	json.NewEncoder(response).Encode(stats.Stats())
}

// Resets all stats
func resetStats(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	response.Header().Set("Access-Control-Allow-Origin", "*")
	response.Header().Set("Content-Type", "application/json")
	traceID := request.Header.Get("Trace-Id")
	if traceID == "" {
		traceID = "VESPER-" + uuid.NewV1().String()
	}
	response.Header().Set("Trace-Id", traceID)
	response.WriteHeader(http.StatusOK)
	stats.ResetStats()
}
