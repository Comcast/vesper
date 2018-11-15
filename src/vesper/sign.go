// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"fmt"
	"io"
	"encoding/json"
	"net/http"
	"time"
	"github.com/httprouter"
	"github.com/satori/go.uuid"
	"vesper/stats"
	kitlog "github.com/go-kit/kit/log"
)

// SResponse
type SResponse struct {
	SigningResponse ErrorBlob `json:"signingResponse"`
}

// -
func signRequest(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	start := time.Now()
	response.Header().Set("Access-Control-Allow-Origin", "*")
	response.Header().Set("Content-Type", "application/json")
	clientIP := getClientIP(request)
	traceID := request.Header.Get("Trace-Id")
	if traceID == "" {
		traceID = "VESPER-" + uuid.NewV1().String()
	}
	response.Header().Set("Trace-Id", traceID)
	stats.IncrSigningRequestCount()
	// verify no query is present
	// verify the request body is correct
	var r map[string]interface{}
	err := json.NewDecoder(request.Body).Decode(&r)
	switch {
	case err == io.EOF:
		// empty request body
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "signRequest")
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4001", "empty request body", nil)
		return
	case err != nil :
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "signRequest")
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4002", "unable to parse request body", nil)
		return
	default:
		// err == nil. continue
	}
	orderedMap, _, _, _, _, errCode, err := validatePayload(r, traceID, clientIP)
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "signRequest")
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, errCode, err.Error(), nil)
		return
	}
	logInfo("type", "signRequest", "traceID", traceID, "clientIP", clientIP, "module", "signRequest", "requestPayload", r)
	x, p := signingCredentials.Signing()
	// at this point, the input has been validated
	hdr := ShakenHdr{	Alg: "ES256", Ppt: "shaken", Typ: "passport", X5u: x}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "signRequest")
		serveHttpResponse(start, response, lg, http.StatusInternalServerError, "error", traceID, "VESPER-5050", fmt.Sprintf("%v - error in converting header to byte array", err), nil)
		return
	}
	claimsBytes, _ := json.Marshal(orderedMap)
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "signRequest")
		serveHttpResponse(start, response, lg, http.StatusInternalServerError, "error", traceID, "VESPER-5051", fmt.Sprintf("%v - error in converting claims to byte array", err), nil)
		return
	}
	canonicalString, sig, err := createSignature(hdrBytes, claimsBytes, p)
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "signRequest")
		serveHttpResponse(start, response, lg, http.StatusInternalServerError, "error", traceID, "VESPER-5052", fmt.Sprintf("%v - error in signing request for request payload", err), nil)
		return
	}
	resp := make(map[string]interface{})
	resp["signingResponse"] = make(map[string]interface{})
	resp["signingResponse"].(map[string]interface{})["identity"] = canonicalString + "." + sig + ";info=<" + x + ">;alg=ES256"
	lg := kitlog.With(glogger, "type", "requestResponseTime", "module", "signRequest", "resp", resp)
	serveHttpResponse(start, response, lg, http.StatusOK, "info", traceID, "", "", resp)
}
