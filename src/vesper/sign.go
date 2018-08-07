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

// SResponse
type SResponse struct {
	SigningResponse ErrorBlob `json:"signingResponse"`
}

// -
func signRequest(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	start := time.Now()
	response.Header().Set("Access-Control-Allow-Origin", "*")
	response.Header().Set("Content-Type", "application/json")
	clientIP := request.RemoteAddr
	traceID := request.Header.Get("Trace-Id")
	if traceID == "" {
		traceID = "VESPER-" + uuid.NewV1().String()
	}
	response.Header().Set("Trace-Id", traceID)

	// verify no query is present
	// verify the request body is correct
	var r map[string]interface{}
	err := json.NewDecoder(request.Body).Decode(&r)
	switch {
	case err == io.EOF:
		// empty request body
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-4001, ReasonString=empty request body", traceID, clientIP)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := SResponse{SigningResponse : ErrorBlob{ReasonCode: "VESPER-4001", ReasonString: "empty request body"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	case err != nil :
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-4002, ReasonString=received invalid json", traceID, clientIP)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := SResponse{SigningResponse : ErrorBlob{ReasonCode: "VESPER-4002", ReasonString: "Unable to parse request body"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	default:
		// err == nil. continue
	}
	orderedMap, _, _, _, _, errCode, err := validatePayload(r, traceID, clientIP)
	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := SResponse{SigningResponse : ErrorBlob{ReasonCode: errCode, ReasonString: err.Error()}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	}

	logInfo("Type=vespersignRequest, TraceID=%v, Module=signRequest, Message=%+v", traceID, r)

	x, p := signingCredentials.Signing()
	// at this point, the input has been validated
	hdr := ShakenHdr{	Alg: "ES256", Ppt: "shaken", Typ: "passport", X5u: x}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-5050, ReasonString=error in converting header to byte array : %v", traceID, clientIP, err)
		response.WriteHeader(http.StatusInternalServerError)
		jsonErr := SResponse{SigningResponse : ErrorBlob{ReasonCode: "VESPER-5050", ReasonString: "error in converting header to byte array"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	}
	claimsBytes, _ := json.Marshal(orderedMap)
	if err != nil {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-5051, ReasonString=error in converting claims to byte array : %v", traceID, clientIP, err)
		response.WriteHeader(http.StatusInternalServerError)
		jsonErr := SResponse{SigningResponse : ErrorBlob{ReasonCode: "VESPER-5051", ReasonString: "error in converting claims to byte array"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	}
	canonicalString, sig, err := createSignature(hdrBytes, claimsBytes, []byte(p))
	if err != nil {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-5052, ReasonString=error in signing request for request payload (%+v) : %v", traceID, clientIP, r, err)
		response.WriteHeader(http.StatusInternalServerError)
		jsonErr := SResponse{SigningResponse : ErrorBlob{ReasonCode: "VESPER-5052", ReasonString: "error in signing request"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	}

	resp := make(map[string]interface{})
	resp["signingResponse"] = make(map[string]interface{})
	resp["signingResponse"].(map[string]interface{})["identity"] = canonicalString + "." + sig + ";info=<" + x + ">;alg=ES256"
	response.WriteHeader(http.StatusOK)
	json.NewEncoder(response).Encode(resp)
	logInfo("Type=vesperRequestResponseTime, TraceID=%v,  Message=time spent in signRequest() : %v", traceID, time.Since(start))
}
