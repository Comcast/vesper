// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"fmt"
	"io"
	"encoding/json"
	"net/http"
	"time"
	"strings"
	"reflect"
	"github.com/httprouter"
	"github.com/satori/go.uuid"
)

// VResponse -- for HTTP response codes used for more than one anomaly
type VResponse struct {
	VerificationResponse ErrorBlob `json:"verificationResponse"`
}

// -
func verifyRequest(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	start := time.Now()
	response.Header().Set("Access-Control-Allow-Origin", "*")
	response.Header().Set("Content-Type", "application/json")
	clientIP := request.RemoteAddr
	traceID := request.Header.Get("Trace-Id")
	if traceID == "" {
		traceID = "VESPER-" + uuid.NewV1().String()
	}
	response.Header().Set("Trace-Id", traceID)

	var iat uint64
	var origTNs, destTNs []string
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
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0100", ReasonString: "empty request body"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	case err != nil :
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=received invalid json", traceID, clientIP);
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0102", ReasonString: "Unable to parse request body"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	default:
		// err == nil
		if !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["identity"]).IsValid() {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=one or more of the require fields missing in request payload (%+v)", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0103", ReasonString: "one or more of the require fields missing in request payload"}}
			json.NewEncoder(response).Encode(jsonErr)
			return
		}
		// request payload should not contain more than the expected fields
		if len(r) != 4 {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=request payload (%+v) has more than expected fields", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0104", ReasonString: "request payload has more than expected fields"}}
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
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0105", ReasonString: "iat value in request payload is 0"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=iat field in request payload (%+v) MUST be a number", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0106", ReasonString: "iat field in request payload MUST be a number"}}
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
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0107", ReasonString: "identity field in request payload is an empty string"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, Message=attest field in request payload (%+v) MUST be a string", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0108", ReasonString: "attest field in request payload MUST be a string"}}
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
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0109", ReasonString: "orig in request payload is an empty object"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			case len(origKeys) > 1 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig in request payload (%+v) should contain only one field", traceID, clientIP, r);
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0110", ReasonString: "orig in request payload should contain only one field"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			default:
				// field should be "tn" only
				if origKeys[0].String() != "tn" {
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r);
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0111", ReasonString: "orig in request payload does not contain field \"tn\""}}
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
				// must be an array
				switch reflect.TypeOf(r["orig"].(map[string]interface{})["tn"]).Kind() {
				case reflect.Slice:
					// empty array object
					ot := reflect.ValueOf(r["orig"].(map[string]interface{})["tn"])
					if ot.Len() == 0 {
						logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig tn in request payload (%+v) is an empty array", traceID, clientIP, r);
						response.WriteHeader(http.StatusBadRequest)
						jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0112", ReasonString: "orig tn in request payload is an empty array"}}
						json.NewEncoder(response).Encode(jsonErr)
						return
					}
					// contains empty string
					for i := 0; i < ot.Len(); i++ {
						tn := ot.Index(i).Elem()
						if tn.Kind() != reflect.String {
							logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=one or more dest tns in request payload (%+v) is not a string", traceID, clientIP, r);
							response.WriteHeader(http.StatusBadRequest)
							jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0113", ReasonString: "one or more orig tns in request payload is not a string"}}
							json.NewEncoder(response).Encode(jsonErr)
							return
						} else {
							if len(strings.TrimSpace(tn.String())) == 0 {
								logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=one or more orig tns in request payload (%+v) is an empty string", traceID, clientIP, r);
								response.WriteHeader(http.StatusBadRequest)
								jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0114", ReasonString: "one or more orig tns in request payload is an empty string"}}
								json.NewEncoder(response).Encode(jsonErr)
								return
							}
							// append
							origTNs = append(origTNs, tn.String())
						}
					}
				default:
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig tn in request payload (%+v) is not an array", traceID, clientIP, r);
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0115", ReasonString: "orig tn in request payload is not an array"}}
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=orig field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0116", ReasonString: "orig field in request payload MUST be a JSON object"}}
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
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0117", ReasonString: "dest in request payload is an empty object"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			case len(destKeys) > 1 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=dest in request payload (%+v) should contain only one field", traceID, clientIP, r);
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0118", ReasonString: "dest in request payload should contain only one field"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			default:
				// field should be "tn" only
				if destKeys[0].String() != "tn" {
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=dest in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r);
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0119", ReasonString: "dest in request payload does not contain field \"tn\""}}
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
						jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0120", ReasonString: "dest tn in request payload is an empty array"}}
						json.NewEncoder(response).Encode(jsonErr)
						return
					}
					// contains empty string
					for i := 0; i < dt.Len(); i++ {
						tn := dt.Index(i).Elem()
						if tn.Kind() != reflect.String {
							logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=one or more dest tns in request payload (%+v) is not a string", traceID, clientIP, r);
							response.WriteHeader(http.StatusBadRequest)
							jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0121", ReasonString: "one or more dest tns in request payload is not a string"}}
							json.NewEncoder(response).Encode(jsonErr)
							return
						} else {
							if len(strings.TrimSpace(tn.String())) == 0 {
								logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=one or more dest tns in request payload (%+v) is an empty string", traceID, clientIP, r);
								response.WriteHeader(http.StatusBadRequest)
								jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0122", ReasonString: "one or more dest tns in request payload is an empty string"}}
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
					jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0123", ReasonString: "dest tn in request payload is not an array"}}
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=dest field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r);
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0124", ReasonString: "dest field in request payload MUST be a JSON object"}}
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
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0125", ReasonString: "Invalid JWT format in identity header in request payload "}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	}
	// extract header from JWT for validation
	// also get the x5u information required to verify signature
	x5u, hh, err := validateHeader(response, traceID, clientIP, token[0])
	if err != nil {
		// function writes to http.ResponseWriter directly
		return
	}
	// extract claims from JWT for validation
	cc, err := validateClaims(response, traceID, clientIP, token[0], origTNs, destTNs, iat)
	if err != nil {
		// function writes to http.ResponseWriter directly
		return
	}

	resp := make(map[string]interface{})
	resp["verificationResponse"] = make(map[string]interface{})
	resp["verificationResponse"].(map[string]interface{})["dest"] = r["dest"]
	resp["verificationResponse"].(map[string]interface{})["iat"] = r["iat"]
	resp["verificationResponse"].(map[string]interface{})["orig"] = r["orig"]
	resp["verificationResponse"].(map[string]interface{})["jwt"] = make(map[string]interface{})
	resp["verificationResponse"].(map[string]interface{})["jwt"].(map[string]interface{})["header"] = hh
	resp["verificationResponse"].(map[string]interface{})["jwt"].(map[string]interface{})["claims"] = cc

	// verify signature
	err = verifySignature(x5u, token[0])
	if err != nil {
		logError("Type=vesperVerifySignature, TraceID=%v, ClientIP=%v, Module=verifyRequest, Message=error in verifying signature : %v", traceID, clientIP, err);
		response.WriteHeader(http.StatusInternalServerError)
		resp["verificationResponse"].(map[string]interface{})["responseCode"] = 500
		resp["verificationResponse"].(map[string]interface{})["reasonString"] = err.Error()
	} else {
		response.WriteHeader(http.StatusOK)
		resp["verificationResponse"].(map[string]interface{})["responseCode"] = 200
		resp["verificationResponse"].(map[string]interface{})["reasonString"] = "verified"
	}
	json.NewEncoder(response).Encode(resp)

	logInfo("Type=vesperRequestResponseTime, TraceID=%v,  Message=time spent in verifyRequest() : %v", traceID, time.Since(start));
}

// validateHeader - validate JWT header
// check if expected key-values exist
func validateHeader(w http.ResponseWriter, traceID, clientIP, j string) (string, map[string]interface{}, error) {
	var x5u string
	s := strings.Split(j, ".")
	// s[0] is the encoded header
	h, err := base64Decode(s[0])
	if err != nil {
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=unable to base64 url decode header part of JWT : %v", traceID, clientIP, err);
		w.WriteHeader(http.StatusInternalServerError)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0150", ReasonString: "unable to base64 url decode header part of JWT "}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(h, &m); err != nil {
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=unable to unmarshal decoded header to map[string]interface{} : %v", traceID, clientIP, err);
		w.WriteHeader(http.StatusInternalServerError)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0151", ReasonString: "unable to unmarshal decoded JWT header"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, err
	}
	if len(m) != 4 {
		// not the expected number of fields in header
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=decoded header does not have the expected number of fields (4)", traceID, clientIP);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0126", ReasonString: "decoded header does not have the expected number of fields (4)"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("decoded header does not have the expected number of fields (4)")
	}
	// err == nil
	if !reflect.ValueOf(m["alg"]).IsValid() || !reflect.ValueOf(m["ppt"]).IsValid() || !reflect.ValueOf(m["typ"]).IsValid() || !reflect.ValueOf(m["x5u"]).IsValid() {
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=one or more of the required fields missing in JWT header (%+v)", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0127", ReasonString: "one or more of the required fields missing in JWT header"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("one or more of the required fields missing in JWT header")
	}

	// alg ...
	switch reflect.TypeOf(m["alg"]).Kind() {
	case reflect.String:
		alg := reflect.ValueOf(m["alg"]).String()
		if alg != "ES256" {
			logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=alg field value (%v) in JWT header is not \"ES256\"", traceID, clientIP, alg);
			w.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0128", ReasonString: "alg field value in JWT header is not \"ES256\""}}
			json.NewEncoder(w).Encode(jsonErr)
			return "", nil, fmt.Errorf("alg field value in JWT header is not \"ES256\"")
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=alg field value (%v) in JWT header is not a string", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0129", ReasonString: "alg field value in JWT header is not a string"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("alg field value in JWT header is not a string")
	}

	// ppt ...
	switch reflect.TypeOf(m["ppt"]).Kind() {
	case reflect.String:
		ppt := reflect.ValueOf(m["ppt"]).String()
		if ppt != "shaken" {
			logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=ppt field value (%v) in JWT header is not \"shaken\"", traceID, clientIP, ppt);
			w.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0130", ReasonString: "ppt field value in JWT header is not \"shaken\""}}
			json.NewEncoder(w).Encode(jsonErr)
			return "", nil, fmt.Errorf("ppt field value in JWT header is not \"shaken\"")
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=ppt field value (%v) in JWT header is not a string", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0131", ReasonString: "ppt field value in JWT header is not a string"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("ppt field value in JWT header is not a string")
	}

	// typ ...
	switch reflect.TypeOf(m["typ"]).Kind() {
	case reflect.String:
		typ := reflect.ValueOf(m["typ"]).String()
		if typ != "passport" {
			logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=typ field value (%v) in JWT header is not \"passport\"", traceID, clientIP, typ);
			w.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0132", ReasonString: "typ field value in JWT header is not \"passport\""}}
			json.NewEncoder(w).Encode(jsonErr)
			return "", nil, fmt.Errorf("typ field value in JWT header is not \"passport\"")
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=typ field value (%v) in JWT header is not a string", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0133", ReasonString: "typ field value in JWT header is not a string"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("typ field value in JWT header is not a string")
	}

	// x5u ...
	switch reflect.TypeOf(m["x5u"]).Kind() {
	case reflect.String:
		x5u = reflect.ValueOf(m["x5u"]).String()
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, Message=x5u field value (%v) in JWT header is not a string", traceID, clientIP, m);
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0134", ReasonString: "x5u field value in JWT header is not a string"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("x5u field value in JWT header is not a string")
	}

	return x5u, m, nil
}

// validateClaims - validate JWT claims
// check if expected key-values exist
func validateClaims(w http.ResponseWriter, traceID, clientIP, j string, oTNs, dTNs []string, iat uint64) (map[string]interface{}, error) {
	logInfo("oTNS %+v dTNS %+v iat %v TOKEN %v", oTNs, dTNs, iat, j)
	s := strings.Split(j, ".")
	// s[0] is the encoded claims
	c, err := base64Decode(s[1])
	if err != nil {
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=validateClaims, Message=unable to base64 url decode claims part of JWT : %v", traceID, clientIP, err);
		w.WriteHeader(http.StatusInternalServerError)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0152", ReasonString: "unable to base64 url decode claims part of JWT "}}
		json.NewEncoder(w).Encode(jsonErr)
		return nil, err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(c, &m); err != nil {
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=validateClaims, Message=unable to unmarshal decoded claims to map[string]interface{} : %v", traceID, clientIP, err);
		w.WriteHeader(http.StatusInternalServerError)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-0153", ReasonString: "unable to unmarshal decoded JWT claims"}}
		json.NewEncoder(w).Encode(jsonErr)
		return nil, err
	}
	//origTNInClaims, iatInClaims, destTNsInClaims, err := validatePayload(w, m, traceID, clientIP)
	_, _, _, errCode, err := validatePayload(m, traceID, clientIP)
	if err != nil {
		// ResponseWriter has been updated in the function
		w.WriteHeader(http.StatusInternalServerError)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: errCode, ReasonString: err.Error()}}
		json.NewEncoder(w).Encode(jsonErr)
		return nil, err
	}
	return m, nil
}
