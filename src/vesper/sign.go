// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"io"
	"encoding/json"
	"net/http"
	"time"
	"github.com/httprouter"
	"github.com/satori/go.uuid"
)

// SigningRequest ...
type SigningResponse struct {
	Identity string `json:"identity"`
}

// -
func signRequest(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	start := time.Now()
	response.Header().Set("Access-Control-Allow-Origin", "*")
	clientIP := request.RemoteAddr
	traceID := request.Header.Get("Trace-Id")
	if traceID == "" {
		traceID = "VESPER-" + uuid.NewV1().String()
	}

	// verify no query is present
	// verify the request body is correct
	var r map[string]interface{}
	err := json.NewDecoder(request.Body).Decode(&r)
	switch {
	case err == io.EOF:
		// empty request body
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=signRequest, Message=empty request body", traceID, clientIP);
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0001", Message: "empty request body"}}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(jsonErr)
		return
	case err != nil :
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=signRequest, Message=received invalid json", traceID, clientIP);
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0002", Message: "Unable to parse request body"}}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(jsonErr)
		return
	default:
		// err == nil
		_, _, _, err = validatePayload(response, r, traceID, clientIP)
		if err != nil {
			// ResponseWriter has been updated in the function
			return
		}
	}
	logInfo("Type=vespersignRequest, TraceID=%v, Module=signRequest, Message=%+v", traceID, r)

	// at this point, the input has been validated
	hdr := ShakenHdr{	Alg: "ES256", Typ: "passport", Ppt: "shaken", X5u: config.Authentication["x5u"].(string)}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, Message=error in converting header to byte array : %v", traceID, clientIP, err);
		response.WriteHeader(http.StatusInternalServerError)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0050", Message: "error in converting header to byte array"}}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(jsonErr)
		return
	}
	claimsBytes, _ := json.Marshal(r)
	if err != nil {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, Message=error in converting claims to byte array : %v", traceID, clientIP, err);
		response.WriteHeader(http.StatusInternalServerError)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0051", Message: "error in converting claims to byte array"}}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(jsonErr)
		return
	}
	canonicalString, sig, err := createSignature(hdrBytes, claimsBytes)
	if err != nil {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, Message=error in signing request for request payload (%+v) : %v", traceID, clientIP, r, err);
		response.WriteHeader(http.StatusInternalServerError)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0052", Message: "error in signing request"}}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(jsonErr)
		return
	}

	var resp SigningResponse
	resp.Identity = canonicalString + "." + sig + ";info=<" + config.Authentication["x5u"].(string) + ";alg=ES256"
	response.WriteHeader(http.StatusOK)
	response.Header().Set("Content-Type", "application/json")
	json.NewEncoder(response).Encode(resp)
	logInfo("Type=vesperRequestResponseTime, TraceID=%v,  Message=time spent in signRequest() : %v", traceID, time.Since(start));
}
