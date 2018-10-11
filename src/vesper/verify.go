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
	kitlog "github.com/go-kit/kit/log"
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
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest")
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4100", "empty request body")
		return
	case err != nil :
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest")
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4102", "unable to parse request body")
		return
	default:
		// err == nil
		if !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["identity"]).IsValid() {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4103", "one or more of the require fields missing in request payload")
			return
		}
		// request payload should not contain more than the expected fields
		if len(r) != 4 {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4104", "request payload has more than expected fields")
			return
		}

		// iat ...
		switch reflect.TypeOf(r["iat"]).Kind() {
		case reflect.Float64:
			iat = int64(reflect.ValueOf(r["iat"]).Float())
			if iat <= 0 {
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4105", "iat value in request payload is <= 0")
				return
			}
		default:
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4106", "iat field in request payload MUST be a number")
			return
		}

		// identity ...
		switch reflect.TypeOf(r["identity"]).Kind() {
		case reflect.String:
			identity = reflect.ValueOf(r["identity"]).String()
			if len(strings.TrimSpace(identity)) == 0 {
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4107", "identity field in request payload is an empty string")
				return
			}
		default:
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4108", "identity field in request payload MUST be a string")
			return
		}

		// orig ...
		switch reflect.TypeOf(r["orig"]).Kind() {
		case reflect.Map:
			origKeys := reflect.ValueOf(r["orig"]).MapKeys()
			switch {
			case len(origKeys) == 0 :
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4109", "orig in request payload is an empty object")
				return
			case len(origKeys) > 1 :
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4110", "orig in request payload should contain only one field")
				return
			default:
				// field should be "tn" only
				if origKeys[0].String() != "tn" {
					lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
					serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4111", "orig in request payload does not contain field \"tn\"")
					return
				}
				// must be an array
				switch reflect.TypeOf(r["orig"].(map[string]interface{})["tn"]).Kind() {
				case reflect.Slice:
					// empty array object
					ot := reflect.ValueOf(r["orig"].(map[string]interface{})["tn"])
					if ot.Len() == 0 {
						lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
						serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4112", "orig tn in request payload is an empty array")
						return
					}
					// contains empty string
					if ot.Len() != 1 {
						lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
						serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4113", "orig tn array contains more than one element in request payload")
						return
					}
					for i := 0; i < ot.Len(); i++ {
						tn := ot.Index(i).Elem()
						if tn.Kind() != reflect.String {
							lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
							serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4114", "orig tn in request payload is not a string")
							return
						} else {
							if len(strings.TrimSpace(tn.String())) == 0 {
								lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
								serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4115", "orig tn in request payload is an empty string")
								return
							}
							// append
							origTN = tn.String()
						}
					}
				default:
					lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
					serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4116", "orig tn in request payload is not an array")
					return
				}
			}
		default:
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4117", "orig field in request payload MUST be a JSON object")
			return
		}

		// dest ...
		switch reflect.TypeOf(r["dest"]).Kind() {
		case reflect.Map:
			destKeys := reflect.ValueOf(r["dest"]).MapKeys()
			switch {
			case len(destKeys) == 0 :
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4118", "dest in request payload is an empty object")
				return
			case len(destKeys) > 1 :
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4119", "dest in request payload should contain only one field")
				return
			default:
				// field should be "tn" only
				if destKeys[0].String() != "tn" {
					lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
					serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4120", "dest in request payload does not contain field \"tn\"")
					return
				}
				// validate "tn" value is of type string and is not an empty string
				switch reflect.TypeOf(r["dest"].(map[string]interface{})["tn"]).Kind() {
				case reflect.Slice:
					// empty array object
					dt := reflect.ValueOf(r["dest"].(map[string]interface{})["tn"])
					if dt.Len() == 0 {
						lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
						serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4121", "dest tn in request payload is an empty array")
						return
					}
					// contains empty string
					for i := 0; i < dt.Len(); i++ {
						tn := dt.Index(i).Elem()
						if tn.Kind() != reflect.String {
							lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
							serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4122", "one or more dest tns in request payload is not a string")
							return
						} else {
							if len(strings.TrimSpace(tn.String())) == 0 {
								lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
								serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4123", "one or more dest tns in request payload is an empty string")
								return
							}
							// append
							destTNs = append(destTNs, tn.String())
						}
					}
				default:
					lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
					serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4124", "dest tn in request payload is not an array")
					return
				}
			}
		default:
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4125", "dest field in request payload MUST be a JSON object")
			return
		}
	}
	logInfo("Type=vesperverifyRequest, TraceID=%v, Module=verifyRequest, Message=%+v", traceID, r)

	// first extract the JWT in identity string
	token := strings.Split(identity, ";")
	// validate identity field
	if len(token) != 4 {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4126", "Identity field does not contain all the relevant parameters in request payload")
		return
	}
	// JWT
	jwt := strings.Split(token[0], ".")
	if len(jwt) != 3 {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4127", "Invalid JWT format in identity field in request payload")
		return
	}
	// Info parameter
	if !regexInfo.MatchString(token[1]) {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4128", "Invalid info parameter in identity field in request payload")
		return
	}
	info := token[1][6:len(token[1])-1]
	// alg
	if !regexAlg.MatchString(token[2]) {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4129", "Invalid alg parameter in identity field in request payload")
		return
	}
	// ppt
	if !regexPpt.MatchString(token[3]) {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4130", "Invalid ppt parameter in identity field in request payload")
		return
	}
	
	// extract header from JWT for validation
	// also get the x5u information required to verify signature
	x5u, hh, err := validateHeader(start, response, traceID, clientIP, token[0])
	if err != nil {
		// function writes to http.ResponseWriter directly
		return
	}
	// compare x5u and info
	if x5u != info {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4131", "x5u value in JWT header does not match info parameter in identity field in request payload")
		return
	}	
	
	// extract claims from JWT for validation
	orderedMap, iatInClaims, err := validateClaims(start, response, traceID, clientIP, token[0], origTN, destTNs, iat, start.Unix())
	if err != nil {
		// function writes to http.ResponseWriter directly
		return
	}
	
	// replay attack validation
	// convert ordered map to json string and check for replay attacks
	claimsString, err := json.Marshal(orderedMap)
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4168", fmt.Sprintf("%v - unable to validate replay attack", err))
		return
	}
	if ok := replayAttackCache.IsPresent(iatInClaims, string(claimsString)); ok {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4169", fmt.Sprintf("possible replay attack - identity header repeated - JWT claims (%+v) is cached", string(claimsString)))
		return
	}

	resp := make(map[string]interface{})
	resp["verificationResponse"] = make(map[string]interface{})
	lg := kitlog.With(glogger, "type", "requestResponseTime", "module", "verifyRequest")
	// verify signature
	code, errCode, err := verifySignature(x5u, token[0], configuration.ConfigurationInstance().VerifyRootCA)
	if err != nil {
		serveHttpResponse(start, response, lg, errCode, "error", traceID, code, fmt.Sprintf("%v - error in verifying signature", err))
		resp["verificationResponse"].(map[string]interface{})["reasonCode"] = code
		resp["verificationResponse"].(map[string]interface{})["reasonString"] = err.Error()
	} else {
		serveHttpResponse(start, response, lg, http.StatusOK, "info", traceID, "", "")
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
}

// validateHeader - validate JWT header
// check if expected key-values exist
func validateHeader(start time.Time, w http.ResponseWriter, traceID, clientIP, j string) (string, map[string]interface{}, error) {
	var x5u string
	s := strings.Split(j, ".")
	// s[0] is the encoded header
	h, err := base64Decode(s[0])
	if err != nil {
		lg := kitlog.With(glogger, "type", "jwtHeader", "clientIP", clientIP, "module", "validateHeader")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4150", fmt.Sprintf("%v - unable to base64 url decode header part of JWT", err))
		return "", nil, err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(h, &m); err != nil {
		lg := kitlog.With(glogger, "type", "jwtHeader", "clientIP", clientIP, "module", "validateHeader")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4151", fmt.Sprintf("%v - unable to unmarshal decoded header to map[string]interface{}", err))
		return "", nil, err
	}
	if len(m) != 4 {
		// not the expected number of fields in header
		lg := kitlog.With(glogger, "type", "jwtHeader", "clientIP", clientIP, "module", "validateHeader")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4132", "decoded header does not have the expected number of fields (4)")
		return "", nil, fmt.Errorf("decoded header does not have the expected number of fields (4)")
	}
	// err == nil
	if !reflect.ValueOf(m["alg"]).IsValid() || !reflect.ValueOf(m["ppt"]).IsValid() || !reflect.ValueOf(m["typ"]).IsValid() || !reflect.ValueOf(m["x5u"]).IsValid() {
		lg := kitlog.With(glogger, "type", "jwtHeader", "clientIP", clientIP, "module", "validateHeader")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4133", "one or more of the required fields missing in JWT header")
		return "", nil, fmt.Errorf("one or more of the required fields missing in JWT header")
	}

	// alg ...
	switch reflect.TypeOf(m["alg"]).Kind() {
	case reflect.String:
		alg := reflect.ValueOf(m["alg"]).String()
		if alg != "ES256" {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader")
			serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4134", "alg field value in JWT header is not \"ES256\"")
			return "", nil, fmt.Errorf("alg field value in JWT header is not \"ES256\"")
		}
	default:
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4135", "alg field in JWT header is not a string")
		return "", nil, fmt.Errorf("alg field value in JWT header is not a string")
	}

	// ppt ...
	switch reflect.TypeOf(m["ppt"]).Kind() {
	case reflect.String:
		ppt := reflect.ValueOf(m["ppt"]).String()
		if ppt != "shaken" {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader")
			serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4136", "ppt field value in JWT header is not \"shaken\"")
			return "", nil, fmt.Errorf("ppt field value in JWT header is not \"shaken\"")
		}
	default:
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4137", "ppt field value in JWT header is not a string")
		return "", nil, fmt.Errorf("ppt field value in JWT header is not a string")
	}

	// typ ...
	switch reflect.TypeOf(m["typ"]).Kind() {
	case reflect.String:
		typ := reflect.ValueOf(m["typ"]).String()
		if typ != "passport" {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader")
			serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4138", "typ field value in JWT header is not \"passport\"")
			return "", nil, fmt.Errorf("typ field value in JWT header is not \"passport\"")
		}
	default:
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4139", "typ field value in JWT header is not a string")
		return "", nil, fmt.Errorf("typ field value in JWT header is not a string")
	}

	// x5u ...
	switch reflect.TypeOf(m["x5u"]).Kind() {
	case reflect.String:
		x5u = reflect.ValueOf(m["x5u"]).String()
	default:
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4140", "x5u field value in JWT header is not a string")
		return "", nil, fmt.Errorf("x5u field value in JWT header is not a string")
	}

	return x5u, m, nil
}

// validateClaims - validate JWT claims
// check if expected key-values exist
func validateClaims(start time.Time, w http.ResponseWriter, traceID, clientIP, j, oTN string, dTNs []string, iat, t int64) (map[string]interface{}, int64, error) {
	logInfo("oTN %v dTNS %+v iat %v TOKEN %v", oTN, dTNs, iat, j)
	s := strings.Split(j, ".")
	// s[0] is the encoded claims
	c, err := base64Decode(s[1])
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4152", fmt.Sprintf("%v - unable to base64 url decode claims part of JWT", err))
		return nil, 0, err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(c, &m); err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4153", fmt.Sprintf("%v - unable to unmarshal decoded claims to map[string]interface{}", err))
		return nil, 0, err
	}
	//origTNInClaims, iatInClaims, destTNsInClaims, err := validatePayload(w, m, traceID, clientIP)
	orderedMap, origTNInClaims, iatInClaims, destTNsInClaims, _, errCode, err := validatePayload(m, traceID, clientIP)
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, errCode, err.Error())
		return nil, 0, err
	}
	// validate orig TN
	if origTNInClaims != oTN {
		es := fmt.Sprintf("orig TN %v in request payload does not match orig TN in JWT claims (%+v)", oTN, m)
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4154", es)
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
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4155", es)
		return nil, 0, fmt.Errorf("%v", es)
	}
	// iat in JWT validation
	if (t > (iatInClaims + configuration.ConfigurationInstance().ValidIatPeriod)) {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims")
		es := fmt.Sprintf("iat value (%v seconds) in JWT claims indicates stale date", iatInClaims)
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "VESPER-4167", es)
		return nil, 0, fmt.Errorf("%v", es)
	}
	return orderedMap, iatInClaims, nil
}
