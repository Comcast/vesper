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
	"vesper/configuration"
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

	var iat int64
	var origTN string
	var destTNs []string
	var identity string
	// verify no query is present
	// verify the request body is correct
	var r map[string]interface{}
	err := json.NewDecoder(request.Body).Decode(&r)
	switch {
	case err == io.EOF:
		// empty request body
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4100, ReasonString=empty request body", traceID, clientIP)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4100", ReasonString: "empty request body"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	case err != nil :
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4102, ReasonString=received invalid json", traceID, clientIP)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4102", ReasonString: "Unable to parse request body"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	default:
		// err == nil
		if !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["identity"]).IsValid() {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4103, ReasonString=one or more of the require fields missing in request payload (%+v)", traceID, clientIP, r)
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4103", ReasonString: "one or more of the require fields missing in request payload"}}
			json.NewEncoder(response).Encode(jsonErr)
			return
		}
		// request payload should not contain more than the expected fields
		if len(r) != 4 {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4104, ReasonString=request payload (%+v) has more than expected fields", traceID, clientIP, r)
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4104", ReasonString: "request payload has more than expected fields"}}
			json.NewEncoder(response).Encode(jsonErr)
			return
		}

		// iat ...
		switch reflect.TypeOf(r["iat"]).Kind() {
		case reflect.Float64:
			iat = int64(reflect.ValueOf(r["iat"]).Float())
			if iat <= 0 {
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4105, ReasonString=iat value in request payload is <= 0", traceID, clientIP, r)
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4105", ReasonString: "iat value in request payload is <= 0"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4106, ReasonString=iat field in request payload (%+v) MUST be a number", traceID, clientIP, r)
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4106", ReasonString: "iat field in request payload MUST be a number"}}
			json.NewEncoder(response).Encode(jsonErr)
			return
		}

		// identity ...
		switch reflect.TypeOf(r["identity"]).Kind() {
		case reflect.String:
			identity = reflect.ValueOf(r["identity"]).String()
			if len(strings.TrimSpace(identity)) == 0 {
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-4107, ReasonString=identity field in request payload (%+v) is an empty string", traceID, clientIP, r)
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4107", ReasonString: "identity field in request payload is an empty string"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-4108, ReasonString=attest field in request payload (%+v) MUST be a string", traceID, clientIP, r)
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4108", ReasonString: "attest field in request payload MUST be a string"}}
			json.NewEncoder(response).Encode(jsonErr)
			return
		}

		// orig ...
		switch reflect.TypeOf(r["orig"]).Kind() {
		case reflect.Map:
			origKeys := reflect.ValueOf(r["orig"]).MapKeys()
			switch {
			case len(origKeys) == 0 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4109, ReasonString=orig in request payload (%+v) is an empty object", traceID, clientIP, r)
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4109", ReasonString: "orig in request payload is an empty object"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			case len(origKeys) > 1 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4110, ReasonString=orig in request payload (%+v) should contain only one field", traceID, clientIP, r)
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4110", ReasonString: "orig in request payload should contain only one field"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			default:
				// field should be "tn" only
				if origKeys[0].String() != "tn" {
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4111, ReasonString=orig in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r)
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4111", ReasonString: "orig in request payload does not contain field \"tn\""}}
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
				// must be an array
				switch reflect.TypeOf(r["orig"].(map[string]interface{})["tn"]).Kind() {
				case reflect.Slice:
					// empty array object
					ot := reflect.ValueOf(r["orig"].(map[string]interface{})["tn"])
					if ot.Len() == 0 {
						logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4112, ReasonString=orig tn in request payload (%+v) is an empty array", traceID, clientIP, r)
						response.WriteHeader(http.StatusBadRequest)
						jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4112", ReasonString: "orig tn in request payload is an empty array"}}
						json.NewEncoder(response).Encode(jsonErr)
						return
					}
					// contains empty string
					if ot.Len() != 1 {
						logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4113, ReasonString=orig tn array contains more than one element in request payload (%+v)", traceID, clientIP, r)
						response.WriteHeader(http.StatusBadRequest)
						jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4113", ReasonString: "orig tn array contains more than one element in request payload"}}
						json.NewEncoder(response).Encode(jsonErr)
						return
					}
					for i := 0; i < ot.Len(); i++ {
						tn := ot.Index(i).Elem()
						if tn.Kind() != reflect.String {
							logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4114, ReasonString=orig tn in request payload (%+v) is not a string", traceID, clientIP, r)
							response.WriteHeader(http.StatusBadRequest)
							jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4114", ReasonString: "orig tn in request payload is not a string"}}
							json.NewEncoder(response).Encode(jsonErr)
							return
						} else {
							if len(strings.TrimSpace(tn.String())) == 0 {
								logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4115, ReasonString=orig tn in request payload (%+v) is an empty string", traceID, clientIP, r)
								response.WriteHeader(http.StatusBadRequest)
								jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4115", ReasonString: "orig tn in request payload is an empty string"}}
								json.NewEncoder(response).Encode(jsonErr)
								return
							}
							// append
							origTN = tn.String()
						}
					}
				default:
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4116, ReasonString=orig tn in request payload (%+v) is not an array", traceID, clientIP, r)
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4116", ReasonString: "orig tn in request payload is not an array"}}
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4117, ReasonString=orig field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r)
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4117", ReasonString: "orig field in request payload MUST be a JSON object"}}
			json.NewEncoder(response).Encode(jsonErr)
			return
		}

		// dest ...
		switch reflect.TypeOf(r["dest"]).Kind() {
		case reflect.Map:
			destKeys := reflect.ValueOf(r["dest"]).MapKeys()
			switch {
			case len(destKeys) == 0 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4118, ReasonString=dest in request payload (%+v) is an empty object", traceID, clientIP, r)
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4118", ReasonString: "dest in request payload is an empty object"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			case len(destKeys) > 1 :
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4119, ReasonString=dest in request payload (%+v) should contain only one field", traceID, clientIP, r)
				response.WriteHeader(http.StatusBadRequest)
				jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4119", ReasonString: "dest in request payload should contain only one field"}}
				json.NewEncoder(response).Encode(jsonErr)
				return
			default:
				// field should be "tn" only
				if destKeys[0].String() != "tn" {
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4120, ReasonString=dest in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r)
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4120", ReasonString: "dest in request payload does not contain field \"tn\""}}
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
				// validate "tn" value is of type string and is not an empty string
				switch reflect.TypeOf(r["dest"].(map[string]interface{})["tn"]).Kind() {
				case reflect.Slice:
					// empty array object
					dt := reflect.ValueOf(r["dest"].(map[string]interface{})["tn"])
					if dt.Len() == 0 {
						logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4121, ReasonString=dest tn in request payload (%+v) is an empty array", traceID, clientIP, r)
						response.WriteHeader(http.StatusBadRequest)
						jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4121", ReasonString: "dest tn in request payload is an empty array"}}
						json.NewEncoder(response).Encode(jsonErr)
						return
					}
					// contains empty string
					for i := 0; i < dt.Len(); i++ {
						tn := dt.Index(i).Elem()
						if tn.Kind() != reflect.String {
							logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4122, ReasonString=one or more dest tns in request payload (%+v) is not a string", traceID, clientIP, r)
							response.WriteHeader(http.StatusBadRequest)
							jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4122", ReasonString: "one or more dest tns in request payload is not a string"}}
							json.NewEncoder(response).Encode(jsonErr)
							return
						} else {
							if len(strings.TrimSpace(tn.String())) == 0 {
								logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4123, ReasonString=one or more dest tns in request payload (%+v) is an empty string", traceID, clientIP, r)
								response.WriteHeader(http.StatusBadRequest)
								jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4123", ReasonString: "one or more dest tns in request payload is an empty string"}}
								json.NewEncoder(response).Encode(jsonErr)
								return
							}
							// append
							destTNs = append(destTNs, tn.String())
						}
					}
				default:
					logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4124, ReasonString=dest tn in request payload (%+v) is not an array", traceID, clientIP, r)
					response.WriteHeader(http.StatusBadRequest)
					jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4124", ReasonString: "dest tn in request payload is not an array"}}
					json.NewEncoder(response).Encode(jsonErr)
					return
				}
			}
		default:
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4125, ReasonString=dest field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r)
			response.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4125", ReasonString: "dest field in request payload MUST be a JSON object"}}
			json.NewEncoder(response).Encode(jsonErr)
			return
		}
	}
	logInfo("Type=vesperverifyRequest, TraceID=%v, Module=verifyRequest, Message=%+v", traceID, r)

	// first extract the JWT in identity string
	token := strings.Split(identity, ";")
	// validate identity field
	if len(token) != 4 {
		logError("Type=vesperIdentity, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4126, ReasonString=Identity field does not contain all the relevant parameters in request payload (%+v)", traceID, clientIP, r)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4126", ReasonString: "Identity field does not contain all the relevant parameters in request payload"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	}
	// JWT
	jwt := strings.Split(token[0], ".")
	if len(jwt) != 3 {
		logError("Type=vesperJwtInIdentity, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4127, ReasonString=Invalid JWT format in identity field in request payload (%+v)", traceID, clientIP, r)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4127", ReasonString: "Invalid JWT format in identity field in request payload"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	}
	// Info parameter
	if !regexInfo.MatchString(token[1]) {
		logError("Type=vesperInfoInIdentity, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4128, ReasonString=Invalid info parameter in identity field in request payload (%+v)", traceID, clientIP, r)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4128", ReasonString: "Invalid info parameter in identity field in request payload"}}
		json.NewEncoder(response).Encode(jsonErr)
		return		
	}
	info := token[1][6:len(token[1])-1]
	// alg
	if !regexAlg.MatchString(token[2]) {
		logError("Type=vesperAlgInIdentity, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4129, ReasonString=Invalid alg parameter in identity field in request payload (%+v)", traceID, clientIP, r)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4129", ReasonString: "Invalid alg parameter in identity field in request payload"}}
		json.NewEncoder(response).Encode(jsonErr)
		return		
	}
	// ppt
	if !regexPpt.MatchString(token[3]) {
		logError("Type=vesperPptInIdentity, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4130, ReasonString=Invalid ppt parameter in identity field in request payload (%+v)", traceID, clientIP, r)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4130", ReasonString: "Invalid ppt parameter in identity field in request payload"}}
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
	// compare x5u and info
	if x5u != info {
		logError("Type=vesperX5uInfoUrl, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4131, ReasonString=x5u value (%v) in JWT header does not match info parameter in identity field in request payload (%+v)", traceID, clientIP, x5u, r)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4131", ReasonString: "x5u value in JWT header does not match info parameter in identity field in request payload"}}
		json.NewEncoder(response).Encode(jsonErr)
		return		
	}	
	
	// extract claims from JWT for validation
	orderedMap, iatInClaims, err := validateClaims(response, traceID, clientIP, token[0], origTN, destTNs, iat, start.Unix())
	if err != nil {
		// function writes to http.ResponseWriter directly
		return
	}
	
	// replay attack validation
	// convert ordered map to json string and check for replay attacks
	claimsString, err := json.Marshal(orderedMap)
	if err != nil {
		es := fmt.Sprintf("%v - unable to validate replay attack", err)
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4168, ReasonString=%v", traceID, clientIP, es)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4168", ReasonString: "unable to validate replay attack"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	}
	if ok := replayAttackCache.IsPresent(iatInClaims, string(claimsString)); ok {
		es := fmt.Sprintf("possible replay attack - identity header repeated - JWT claims (%+v) is cached", string(claimsString))
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4169, ReasonString=%v", traceID, clientIP, es)
		response.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4169", ReasonString: "possible replay attack"}}
		json.NewEncoder(response).Encode(jsonErr)
		return
	}

	resp := make(map[string]interface{})
	resp["verificationResponse"] = make(map[string]interface{})
	// verify signature
	code, errCode, err := verifySignature(x5u, token[0], configuration.ConfigurationInstance().VerifyRootCA)
	if err != nil {
		logError("Type=vesperVerifySignature, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=%v, ReasonString=error in verifying signature : %v", traceID, clientIP, code, err)
		response.WriteHeader(errCode)
		resp["verificationResponse"].(map[string]interface{})["reasonCode"] = code
		resp["verificationResponse"].(map[string]interface{})["reasonString"] = err.Error()
	} else {
		response.WriteHeader(http.StatusOK)
		resp["verificationResponse"].(map[string]interface{})["dest"] = r["dest"]
		resp["verificationResponse"].(map[string]interface{})["iat"] = r["iat"]
		resp["verificationResponse"].(map[string]interface{})["orig"] = r["orig"]
		resp["verificationResponse"].(map[string]interface{})["jwt"] = make(map[string]interface{})
		resp["verificationResponse"].(map[string]interface{})["jwt"].(map[string]interface{})["header"] = hh
		resp["verificationResponse"].(map[string]interface{})["jwt"].(map[string]interface{})["claims"] = orderedMap
		// cache claims in identity header to validate replay attacks in future
		// note that caching happens only if verification is successful
		replayAttackCache.Add(iatInClaims, string(claimsString))
	}
	json.NewEncoder(response).Encode(resp)
	logInfo("Type=vesperRequestResponseTime, TraceID=%v,  Message=time spent in verifyRequest() : %v", traceID, time.Since(start))
}

// validateHeader - validate JWT header
// check if expected key-values exist
func validateHeader(w http.ResponseWriter, traceID, clientIP, j string) (string, map[string]interface{}, error) {
	var x5u string
	s := strings.Split(j, ".")
	// s[0] is the encoded header
	h, err := base64Decode(s[0])
	if err != nil {
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4150, ReasonString=unable to base64 url decode header part of JWT : %v", traceID, clientIP, err)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4150", ReasonString: "unable to base64 url decode header part of JWT "}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(h, &m); err != nil {
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4151, ReasonString=unable to unmarshal decoded header to map[string]interface{} : %v", traceID, clientIP, err)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4151", ReasonString: "unable to unmarshal decoded JWT header"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, err
	}
	if len(m) != 4 {
		// not the expected number of fields in header
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4132, ReasonString=decoded header does not have the expected number of fields (4)", traceID, clientIP)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4132", ReasonString: "decoded header does not have the expected number of fields (4)"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("decoded header does not have the expected number of fields (4)")
	}
	// err == nil
	if !reflect.ValueOf(m["alg"]).IsValid() || !reflect.ValueOf(m["ppt"]).IsValid() || !reflect.ValueOf(m["typ"]).IsValid() || !reflect.ValueOf(m["x5u"]).IsValid() {
		logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4133, ReasonString=one or more of the required fields missing in JWT header (%+v)", traceID, clientIP, m)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4133", ReasonString: "one or more of the required fields missing in JWT header"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("one or more of the required fields missing in JWT header")
	}

	// alg ...
	switch reflect.TypeOf(m["alg"]).Kind() {
	case reflect.String:
		alg := reflect.ValueOf(m["alg"]).String()
		if alg != "ES256" {
			logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4134, ReasonString=alg field value (%v) in JWT header is not \"ES256\"", traceID, clientIP, alg)
			w.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4134", ReasonString: "alg field value in JWT header is not \"ES256\""}}
			json.NewEncoder(w).Encode(jsonErr)
			return "", nil, fmt.Errorf("alg field value in JWT header is not \"ES256\"")
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4135, ReasonString=alg field value (%v) in JWT header is not a string", traceID, clientIP, m)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4135", ReasonString: "alg field value in JWT header is not a string"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("alg field value in JWT header is not a string")
	}

	// ppt ...
	switch reflect.TypeOf(m["ppt"]).Kind() {
	case reflect.String:
		ppt := reflect.ValueOf(m["ppt"]).String()
		if ppt != "shaken" {
			logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4136, ReasonString=ppt field value (%v) in JWT header is not \"shaken\"", traceID, clientIP, ppt)
			w.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4136", ReasonString: "ppt field value in JWT header is not \"shaken\""}}
			json.NewEncoder(w).Encode(jsonErr)
			return "", nil, fmt.Errorf("ppt field value in JWT header is not \"shaken\"")
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4137, ReasonString=ppt field value (%v) in JWT header is not a string", traceID, clientIP, m)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4137", ReasonString: "ppt field value in JWT header is not a string"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("ppt field value in JWT header is not a string")
	}

	// typ ...
	switch reflect.TypeOf(m["typ"]).Kind() {
	case reflect.String:
		typ := reflect.ValueOf(m["typ"]).String()
		if typ != "passport" {
			logError("Type=vesperJWTHeader, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4138, ReasonString=typ field value (%v) in JWT header is not \"passport\"", traceID, clientIP, typ)
			w.WriteHeader(http.StatusBadRequest)
			jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4138", ReasonString: "typ field value in JWT header is not \"passport\""}}
			json.NewEncoder(w).Encode(jsonErr)
			return "", nil, fmt.Errorf("typ field value in JWT header is not \"passport\"")
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4139, ReasonString=typ field value (%v) in JWT header is not a string", traceID, clientIP, m)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4139", ReasonString: "typ field value in JWT header is not a string"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("typ field value in JWT header is not a string")
	}

	// x5u ...
	switch reflect.TypeOf(m["x5u"]).Kind() {
	case reflect.String:
		x5u = reflect.ValueOf(m["x5u"]).String()
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validateHeader, ReasonCode=VESPER-4140, ReasonString=x5u field value (%v) in JWT header is not a string", traceID, clientIP, m)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4140", ReasonString: "x5u field value in JWT header is not a string"}}
		json.NewEncoder(w).Encode(jsonErr)
		return "", nil, fmt.Errorf("x5u field value in JWT header is not a string")
	}

	return x5u, m, nil
}

// validateClaims - validate JWT claims
// check if expected key-values exist
func validateClaims(w http.ResponseWriter, traceID, clientIP, j, oTN string, dTNs []string, iat, t int64) (map[string]interface{}, int64, error) {
	logInfo("oTN %v dTNS %+v iat %v TOKEN %v", oTN, dTNs, iat, j)
	s := strings.Split(j, ".")
	// s[0] is the encoded claims
	c, err := base64Decode(s[1])
	if err != nil {
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=validateClaims, ReasonCode=VESPER-4152, ReasonString=unable to base64 url decode claims part of JWT : %v", traceID, clientIP, err)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4152", ReasonString: "unable to base64 url decode claims part of JWT "}}
		json.NewEncoder(w).Encode(jsonErr)
		return nil, 0, err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(c, &m); err != nil {
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=validateClaims, ReasonCode=VESPER-4153, ReasonString=unable to unmarshal decoded claims to map[string]interface{} : %v", traceID, clientIP, err)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4153", ReasonString: "unable to unmarshal decoded JWT claims"}}
		json.NewEncoder(w).Encode(jsonErr)
		return nil, 0, err
	}
	//origTNInClaims, iatInClaims, destTNsInClaims, err := validatePayload(w, m, traceID, clientIP)
	orderedMap, origTNInClaims, iatInClaims, destTNsInClaims, _, errCode, err := validatePayload(m, traceID, clientIP)
	if err != nil {
		// ResponseWriter has been updated in the function
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: errCode, ReasonString: err.Error()}}
		json.NewEncoder(w).Encode(jsonErr)
		return nil, 0, err
	}
	// validate orig TN
	if origTNInClaims != oTN {
		es := fmt.Sprintf("orig TN %v in request payload does not match orig TN in JWT claims (%+v)", oTN, m)
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=validateClaims, ReasonCode=VESPER-4154, ReasonString=%v", traceID, clientIP, es)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4154", ReasonString: "orig TN in request payload does not match orig TN in JWT claims"}}
		json.NewEncoder(w).Encode(jsonErr)
		return nil, 0, fmt.Errorf("%v", es)
	}
	// validate dest TNs
	isMatch := false
	if len(dTNs) == len(destTNsInClaims) {
		for _, v := range dTNs {
			// reset 
			isMatch = false
			for _, vv := range destTNsInClaims {
				if v == vv {
					isMatch = true
					break
				} 
			}
			if !isMatch {
				break
			}
		}
	}
	if !isMatch {
		es := fmt.Sprintf("dest TNs %+v in request payload does not match dest TNs in JWT claims (%+v)", dTNs, m)
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=validateClaims, ReasonCode=VESPER-4155, ReasonString=%v", traceID, clientIP, es)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4155", ReasonString: "dest TNs in request payload does not match dest TNs in JWT claims"}}
		json.NewEncoder(w).Encode(jsonErr)
		return nil, 0, fmt.Errorf("%v", es)
	}
	// iat in JWT validation
	if (t > (iatInClaims + configuration.ConfigurationInstance().ValidIatPeriod)) {
		es := fmt.Sprintf("iat value (%v seconds) in JWT claims indicates stale date", iatInClaims)
		logError("Type=vesperJWTClaims, TraceID=%v, ClientIP=%v, Module=verifyRequest, ReasonCode=VESPER-4167, ReasonString=%v", traceID, clientIP, es)
		w.WriteHeader(http.StatusBadRequest)
		jsonErr := VResponse{VerificationResponse : ErrorBlob{ReasonCode: "VESPER-4167", ReasonString: "iat value in JWT claims indicates stale date"}}
		json.NewEncoder(w).Encode(jsonErr)
		return nil, 0, fmt.Errorf("%v", es)
	}
	return orderedMap, iatInClaims, nil
}
