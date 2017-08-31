// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"fmt"
	"io"
	"encoding/json"
	"encoding/base64"
	"net/http"
	"time"
	"strings"
	"reflect"
	"github.com/httprouter"
	"github.com/satori/go.uuid"
)

// Returns true is a slice contains a duplicate
func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

// -
func verifyRequest(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	start := time.Now()
	response.Header().Set("Access-Control-Allow-Origin", "*")
	clientIP := request.RemoteAddr
	traceID := request.Header.Get("Trace-Id")
	if traceID == "" {
		traceID = "VESPER-" + uuid.NewV1().String()
	}
	var origTN string
	var iat uint64
	var destTNs []string
	var identity string
	// verify no query is present
	// verify the request body is correct
	var r map[string]interface{}
	err := json.NewDecoder(request.Body).Decode(&r)
	switch {
	case err == io.EOF:
		// empty request body
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=empty request body", traceID, clientIP);
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0100", Message: "empty request body"}}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(jsonErr)
		return
	case err != nil :
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=received invalid json", traceID, clientIP);
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0102", Message: "Unable to parse request body"}}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(jsonErr)
		return
	default:
		// err == nil
		if !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["identity"]).IsValid() {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=one or more of the require fields missing in request payload (%+v)", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0103", Message: "one or more of the require fields missing in request payload"}}
			response.Header().Set("Content-Type", "application/json")
			json.NewEncoder(response).Encode(jsonErr)
			return
		}
		// request payload should not contain more than the expected fields
		if len(r) != 4 {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=request payload (%+v) has more than expected fields", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0104", Message: "request payload has more than expected fields"}}
			response.Header().Set("Content-Type", "application/json")
			json.NewEncoder(response).Encode(jsonErr)
			return
		}

		// iat ...
		switch reflect.TypeOf(r["iat"]).Kind() {
		case reflect.Float64:
			iat = uint64(reflect.ValueOf(r["iat"]).Float())
			if iat == 0 {
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=iat value in request payload is 0", traceID, clientIP, r);
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0105", Message: "iat value in request payload is 0"}}
				response.Header().Set("Content-Type", "application/json")
				json.NewEncoder(response).Encode(jsonErr)
				return
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=iat field in request payload (%+v) MUST be a number", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0106", Message: "iat field in request payload MUST be a number"}}
			response.Header().Set("Content-Type", "application/json")
			json.NewEncoder(response).Encode(jsonErr)
			return
		}

		// identity ...
		switch reflect.TypeOf(r["identity"]).Kind() {
		case reflect.String:
			identity = reflect.ValueOf(r["identity"]).String()
			if len(strings.TrimSpace(identity)) == 0 {
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, Message=identity field in request payload (%+v) is an empty string", traceID, clientIP, r);
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0107", Message: "identity field in request payload is an empty string"}}
				response.Header().Set("Content-Type", "application/json")
				json.NewEncoder(response).Encode(jsonErr)
				return
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, Message=attest field in request payload (%+v) MUST be a string", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0108", Message: "attest field in request payload MUST be a string"}}
			response.Header().Set("Content-Type", "application/json")
			json.NewEncoder(response).Encode(jsonErr)
			return
		}

		// orig ...
		switch reflect.TypeOf(r["orig"]).Kind() {
		case reflect.Map:
			origKeys := reflect.ValueOf(r["orig"]).MapKeys()
			switch {
			case len(origKeys) == 0 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig in request payload (%+v) is an empty object", traceID, clientIP, r);
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0109", Message: "orig in request payload is an empty object"}}
				response.Header().Set("Content-Type", "application/json")
				json.NewEncoder(response).Encode(jsonErr)
				return
			case len(origKeys) > 1 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig in request payload (%+v) should contain only one field", traceID, clientIP, r);
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0110", Message: "orig in request payload should contain only one field"}}
				response.Header().Set("Content-Type", "application/json")
				json.NewEncoder(response).Encode(jsonErr)
				return
			default:
				// field should be "tn" only
				if origKeys[0].String() != "tn" {
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r);
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0111", Message: "orig in request payload does not contain field \"tn\""}}
					response.Header().Set("Content-Type", "application/json")
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
				// validate "tn" value is of type string and is not an empty string
				_, ok := r["orig"].(map[string]interface{})["tn"].(string)
				if !ok {
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig tn in request payload (%+v) is not of type string", traceID, clientIP, r);
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0112", Message: "orig tn in request payload is not of type string"}}
					response.Header().Set("Content-Type", "application/json")
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
				origTN = r["orig"].(map[string]interface{})["tn"].(string)
				if len(strings.TrimSpace(origTN)) == 0 {
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig tn in request payload (%+v) is an empty string", traceID, clientIP, r);
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0113", Message: "orig tn in request payload is an empty string"}}
					response.Header().Set("Content-Type", "application/json")
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0114", Message: "orig field in request payload MUST be a JSON object"}}
			response.Header().Set("Content-Type", "application/json")
			json.NewEncoder(response).Encode(jsonErr)
			return
		}

		// dest ...
		switch reflect.TypeOf(r["dest"]).Kind() {
		case reflect.Map:
			destKeys := reflect.ValueOf(r["dest"]).MapKeys()
			switch {
			case len(destKeys) == 0 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=dest in request payload (%+v) is an empty object", traceID, clientIP, r);
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0115", Message: "dest in request payload is an empty object"}}
				response.Header().Set("Content-Type", "application/json")
				json.NewEncoder(response).Encode(jsonErr)
				return
			case len(destKeys) > 1 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=dest in request payload (%+v) should contain only one field", traceID, clientIP, r);
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0116", Message: "dest in request payload should contain only one field"}}
				response.Header().Set("Content-Type", "application/json")
				json.NewEncoder(response).Encode(jsonErr)
				return
			default:
				// field should be "tn" only
				if destKeys[0].String() != "tn" {
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=dest in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r);
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0117", Message: "dest in request payload does not contain field \"tn\""}}
					response.Header().Set("Content-Type", "application/json")
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
				// validate "tn" value is of type string and is not an empty string
				switch reflect.TypeOf(r["dest"].(map[string]interface{})["tn"]).Kind() {
				case reflect.Slice:
					// empty array object
					dt := reflect.ValueOf(r["dest"].(map[string]interface{})["tn"])
					if dt.Len() == 0 {
						logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=dest tn in request payload (%+v) is an empty array", traceID, clientIP, r);
						response.WriteHeader(http.StatusBadRequest)
						jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0118", Message: "dest tn in request payload is an empty array"}}
						response.Header().Set("Content-Type", "application/json")
						json.NewEncoder(response).Encode(jsonErr)
						return
					}
					// contains empty string
					for i := 0; i < dt.Len(); i++ {
						tn := dt.Index(i).Elem()
						if tn.Kind() != reflect.String {
							logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=one or more dest tns in request payload (%+v) is not a string", traceID, clientIP, r);
							response.WriteHeader(http.StatusBadRequest)
							jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0119", Message: "one or more dest tns in request payload is not a string"}}
							response.Header().Set("Content-Type", "application/json")
							json.NewEncoder(response).Encode(jsonErr)
							return
						} else {
							if len(strings.TrimSpace(tn.String())) == 0 {
								logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=one or more dest tns in request payload (%+v) is an empty string", traceID, clientIP, r);
								response.WriteHeader(http.StatusBadRequest)
								jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0120", Message: "one or more dest tns in request payload is an empty string"}}
								response.Header().Set("Content-Type", "application/json")
								json.NewEncoder(response).Encode(jsonErr)
								return
							}
							// append
							destTNs = append(destTNs, tn.String())
						}
					}
				default:
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=dest tn in request payload (%+v) is not an array", traceID, clientIP, r);
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0121", Message: "dest tn in request payload is not an array"}}
					response.Header().Set("Content-Type", "application/json")
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=dest field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0122", Message: "dest field in request payload MUST be a JSON object"}}
			response.Header().Set("Content-Type", "application/json")
			json.NewEncoder(response).Encode(jsonErr)
			return
		}
	}
	logInfo("Type=vesperverifyRequest, TraceID=%v, Module=verifyRequest, Message=%+v", traceID, r)

	// first extract the JWT in identity string
	token := strings.Split(identity, ";")
	jwt := strings.Split(token[0], ".")
	if len(jwt) != 3 {
		logError("Type=vesperJwtFormat, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=Invalid JWT format in identity header in request payload (%+v)", traceID, clientIP, r);
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0123", Message: "Invalid JWT format in identity header in request payload "}}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(jsonErr)
		return
	}
	// extract header from JWT for validation
	// also get the x5u information required to verify signature
	x5u, err := validateHeader(response, traceID, clientIP, token[0])
	if err != nil {
		// function writes to http.ResponseWriter directly
		return
	}

	// verify signature
	err = verifySignature(x5u, token[0])
	if err != nil {
		logError("Type=vesperVerifySignature, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=error in verifying signature : %v", traceID, clientIP, err);
		response.WriteHeader(http.StatusInternalServerError)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0150", Message: "error in verifying signature"}}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(jsonErr)
		return
	}

	// extract claims from JWT for validation
	err = validateClaims(response, traceID, clientIP, token[0], origTN, destTNs, iat)
	if err != nil {
		// function writes to http.ResponseWriter directly
		return
	}

	logInfo("Type=vesperRequestResponseTime, TraceID=%v,  Message=time spent in verifyRequest() : %v", traceID, time.Since(start));
}

// validateHeader - validate JWT header
// check if expected key-values exist
func validateHeader(w http.ResponseWriter, traceID, clientIP, j string) (string, error) {
	var x5u string
	s := strings.Split(j, ".")
	// s[0] is the encoded header
	h, err := base64.URLEncoding.DecodeString(s[0])
	if err != nil {
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=unable to base64 url decode header part of JWT : %v", traceID, clientIP, err);
		w.WriteHeader(http.StatusInternalServerError)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0150", Message: "unable to base64 url decode header part of JWT "}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return "", err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(h, &m); err != nil {
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=unable to unmarshal decoded header to map[string]interface{} : %v", traceID, clientIP, err);
		w.WriteHeader(http.StatusInternalServerError)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0151", Message: "unable to unmarshal decoded JWT header"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return "", err
	}
	if len(m) != 4 {
		// not the expected number of fields in header
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=decoded header does not have the expected number of fields (4)", traceID, clientIP);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0124", Message: "decoded header does not have the expected number of fields (4)"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return "", fmt.Errorf("decoded header does not have the expected number of fields (4)")
	}
	// err == nil
	if !reflect.ValueOf(m["alg"]).IsValid() || !reflect.ValueOf(m["ppt"]).IsValid() || !reflect.ValueOf(m["typ"]).IsValid() || !reflect.ValueOf(m["x5u"]).IsValid() {
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=one or more of the required fields missing in JWT header (%+v)", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0125", Message: "one or more of the required fields missing in JWT header"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return "", fmt.Errorf("one or more of the required fields missing in JWT header")
	}

	// alg ...
	switch reflect.TypeOf(m["alg"]).Kind() {
	case reflect.String:
		alg := reflect.ValueOf(m["alg"]).String()
		if alg != "ES256" {
			logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=alg field value (%v) in JWT header is not \"ES256\"", traceID, clientIP, alg);
			w.WriteHeader(http.StatusBadRequest)
			jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0126", Message: "alg field value in JWT header is not \"ES256\""}}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jsonErr)
			return "", fmt.Errorf("alg field value in JWT header is not \"ES256\"")
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=alg field value (%v) in JWT header is not a string", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0127", Message: "alg field value in JWT header is not a string"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return "", fmt.Errorf("alg field value in JWT header is not a string")
	}

	// ppt ...
	switch reflect.TypeOf(m["ppt"]).Kind() {
	case reflect.String:
		ppt := reflect.ValueOf(m["ppt"]).String()
		if ppt != "shaken" {
			logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=ppt field value (%v) in JWT header is not \"shaken\"", traceID, clientIP, ppt);
			w.WriteHeader(http.StatusBadRequest)
			jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0128", Message: "ppt field value in JWT header is not \"shaken\""}}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jsonErr)
			return "", fmt.Errorf("ppt field value in JWT header is not \"shaken\"")
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=ppt field value (%v) in JWT header is not a string", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0129", Message: "ppt field value in JWT header is not a string"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return "", fmt.Errorf("ppt field value in JWT header is not a string")
	}

	// typ ...
	switch reflect.TypeOf(m["typ"]).Kind() {
	case reflect.String:
		typ := reflect.ValueOf(m["typ"]).String()
		if typ != "passport" {
			logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=typ field value (%v) in JWT header is not \"passport\"", traceID, clientIP, typ);
			w.WriteHeader(http.StatusBadRequest)
			jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0130", Message: "typ field value in JWT header is not \"passport\""}}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jsonErr)
			return "", fmt.Errorf("typ field value in JWT header is not \"passport\"")
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=typ field value (%v) in JWT header is not a string", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0131", Message: "typ field value in JWT header is not a string"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return "", fmt.Errorf("typ field value in JWT header is not a string")
	}

	// x5u ...
	switch reflect.TypeOf(m["x5u"]).Kind() {
	case reflect.String:
		x5u = reflect.ValueOf(m["x5u"]).String()
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=x5u field value (%v) in JWT header is not a string", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0132", Message: "x5u field value in JWT header is not a string"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return "", fmt.Errorf("x5u field value in JWT header is not a string")
	}

	return x5u, nil
}

// validateClaims - validate JWT claims
// check if expected key-values exist
func validateClaims(w http.ResponseWriter, traceID, clientIP, j, oTN string, dTNs []string, iat uint64) error {
	s := strings.Split(j, ".")
	// s[0] is the encoded claims
	c, err := base64.URLEncoding.DecodeString(s[1])
	if err != nil {
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=validateClaims, Message=unable to base64 url decode claims part of JWT : %v", traceID, clientIP, err);
		w.WriteHeader(http.StatusInternalServerError)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0152", Message: "unable to base64 url decode claims part of JWT "}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(c, &m); err != nil {
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=validateClaims, Message=unable to unmarshal decoded claims to map[string]interface{} : %v", traceID, clientIP, err);
		w.WriteHeader(http.StatusInternalServerError)
		jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0153", Message: "unable to unmarshal decoded JWT claims"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonErr)
		return err
	}
	origTNInClaims, iatInClaims, destTNsInClaims, err := validatePayload(w, m, traceID, clientIP)
	if err != nil {
		// ResponseWriter has been updated in the function
		return err
	}

	// compare origTN in request payload and JWT claims
	if origTNInClaims != oTN {

	}

	// compare destTNs in request payload and JWT claims
	// we need to list all destTNs in request payload that are not present in JWT claims in the identity header
	var newDestTNs []string
	for _, dt := range dTNs {
		if !stringInSlice(dt, destTNsInClaims) {
			newDestTNs = append(newDestTNs, dt)
		}
	}
	if len(newDestTNs) > 0 {

	}
	// compare origTN in request payload and JWT claims
	if origTNInClaims != oTN {

	}

	return nil
}
