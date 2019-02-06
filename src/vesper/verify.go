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
	"vesper/stats"
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
	clientIP := getClientIP(request)
	traceID := request.Header.Get("Trace-Id")
	if traceID == "" {
		traceID = "VESPER-" + uuid.NewV1().String()
	}
	response.Header().Set("Trace-Id", traceID)
	stats.IncrVerificationRequestCount()
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
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "error", err)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4100", nil)
		return
	case err != nil :
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "error", err)
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4102", nil)
		return
	default:
		// err == nil
		if !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["identity"]).IsValid() {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "one or more of the require fields missing in request payload")
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4103", nil)
			return
		}
		// request payload should not contain more than the expected fields
		if len(r) != 4 {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "request payload has more than expected fields")
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4104", nil)
			return
		}

		// iat ...
		switch reflect.TypeOf(r["iat"]).Kind() {
		case reflect.Float64:
			iat = int64(reflect.ValueOf(r["iat"]).Float())
			if iat <= 0 {
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "iat value in request payload is <= 0")
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4105", nil)
				return
			}
		default:
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "iat field in request payload MUST be a number")
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4106", nil)
			return
		}

		// identity ...
		switch reflect.TypeOf(r["identity"]).Kind() {
		case reflect.String:
			identity = reflect.ValueOf(r["identity"]).String()
			if len(strings.TrimSpace(identity)) == 0 {
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "identity field in request payload is an empty string")
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4107", nil)
				return
			}
		default:
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "identity field in request payload MUST be a string")
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4108", nil)
			return
		}

		// orig ...
		switch reflect.TypeOf(r["orig"]).Kind() {
		case reflect.Map:
			origKeys := reflect.ValueOf(r["orig"]).MapKeys()
			switch {
			case len(origKeys) == 0 :
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "orig in request payload is an empty object")
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4109", nil)
				return
			case len(origKeys) > 1 :
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "orig in request payload should contain only one field")
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4110", nil)
				return
			default:
				// field should be "tn" only
				if origKeys[0].String() != "tn" {
					lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "orig in request payload does not contain field \"tn\"")
					serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4111", nil)
					return
				}
				// must be an array
				switch reflect.TypeOf(r["orig"].(map[string]interface{})["tn"]).Kind() {
				case reflect.Slice:
					// empty array object
					ot := reflect.ValueOf(r["orig"].(map[string]interface{})["tn"])
					if ot.Len() == 0 {
						lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "orig tn in request payload is an empty array")
						serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4112", nil)
						return
					}
					// contains empty string
					if ot.Len() != 1 {
						lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "orig tn array contains more than one element in request payload")
						serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4113", nil)
						return
					}
					for i := 0; i < ot.Len(); i++ {
						tn := ot.Index(i).Elem()
						if tn.Kind() != reflect.String {
							lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "orig tn in request payload is not a string")
							serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4114", nil)
							return
						} else {
							if len(strings.TrimSpace(tn.String())) == 0 {
								lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "orig tn in request payload is an empty string")
								serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4115", nil)
								return
							}
							// append
							origTN = tn.String()
						}
					}
				default:
					lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "orig tn in request payload is not an array")
					serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4116", nil)
					return
				}
			}
		default:
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "orig field in request payload MUST be a JSON object")
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4117", nil)
			return
		}

		// dest ...
		switch reflect.TypeOf(r["dest"]).Kind() {
		case reflect.Map:
			destKeys := reflect.ValueOf(r["dest"]).MapKeys()
			switch {
			case len(destKeys) == 0 :
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4118", "dest in request payload is an empty object", nil)
				return
			case len(destKeys) > 1 :
				lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
				serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4119", "dest in request payload should contain only one field", nil)
				return
			default:
				// field should be "tn" only
				if destKeys[0].String() != "tn" {
					lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
					serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4120", "dest in request payload does not contain field \"tn\"", nil)
					return
				}
				// validate "tn" value is of type string and is not an empty string
				switch reflect.TypeOf(r["dest"].(map[string]interface{})["tn"]).Kind() {
				case reflect.Slice:
					// empty array object
					dt := reflect.ValueOf(r["dest"].(map[string]interface{})["tn"])
					if dt.Len() == 0 {
						lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
						serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4121", "dest tn in request payload is an empty array", nil)
						return
					}
					// contains empty string
					for i := 0; i < dt.Len(); i++ {
						tn := dt.Index(i).Elem()
						if tn.Kind() != reflect.String {
							lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
							serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4122", "one or more dest tns in request payload is not a string", nil)
							return
						} else {
							if len(strings.TrimSpace(tn.String())) == 0 {
								lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
								serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4123", "one or more dest tns in request payload is an empty string", nil)
								return
							}
							// append
							destTNs = append(destTNs, tn.String())
						}
					}
				default:
					lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
					serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4124", "dest tn in request payload is not an array", nil)
					return
				}
			}
		default:
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r)
			serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "VESPER-4125", "dest field in request payload MUST be a JSON object", nil)
			return
		}
	}
	logInfo("type", "verifyRequest", "traceID", traceID, "module", "verifyRequest", "requestPayload", r)

	// first extract the JWT in identity string
	token := strings.Split(identity, ";")
	// validate identity field
	if len(token) < 2 {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "Identity field does not contain all the relevant parameters in request payload")
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4126", nil)
		return
	}
	// JWT
	jwt := strings.Split(token[0], ".")
	if len(jwt) != 3 {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "Invalid JWT format in identity field in request payload")
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4127", nil)
		return
	}
	// Info parameter
	if !regexInfo.MatchString(token[1]) {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "Invalid info parameter in identity field in request payload")
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4128", nil)
		return
	}
	info := token[1][6:len(token[1])-1]
	
	// extract header from JWT for validation
	// also get the x5u information required to verify signature
	x5u, hh, err := validateHeader(start, response, traceID, clientIP, token[0])
	if err != nil {
		// function writes to http.ResponseWriter directly
		return
	}
	// compare x5u and info
	if x5u != info {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", "x5u value in JWT header does not match info parameter in identity field in request payload")
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4131", nil)
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
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", fmt.Sprintf("%v - unable to validate replay attack", err))
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4168", nil)
		return
	}
	if ok := replayAttackCache.IsPresent(iatInClaims, string(claimsString)); ok {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "verifyRequest", "requestPayload", r, "error", fmt.Sprintf("possible replay attack - identity header repeated - JWT claims (%+v) is cached", string(claimsString)))
		serveHttpResponse(start, response, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4169", nil)
		return
	}

	// verify signature
	code, httpCode, err := verifySignature(x5u, token[0], configuration.ConfigurationInstance().VerifyRootCA)
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestResponseTime", "module", "verifyRequest", "error", fmt.Sprintf("%v - error in verifying signature", err))
		serveHttpResponse(start, response, lg, httpCode, "error", "verificationResponse", traceID, code, nil)
		return
	}
	lg := kitlog.With(glogger, "type", "requestResponseTime", "module", "verifyRequest")
	resp := make(map[string]interface{})
	resp["verificationResponse"] = make(map[string]interface{})
	resp["verificationResponse"].(map[string]interface{})["dest"] = r["dest"]
	resp["verificationResponse"].(map[string]interface{})["iat"] = r["iat"]
	resp["verificationResponse"].(map[string]interface{})["orig"] = r["orig"]
	resp["verificationResponse"].(map[string]interface{})["jwt"] = make(map[string]interface{})
	resp["verificationResponse"].(map[string]interface{})["jwt"].(map[string]interface{})["header"] = hh
	resp["verificationResponse"].(map[string]interface{})["jwt"].(map[string]interface{})["claims"] = orderedMap
	// cache claims in identity header to validate replay attacks in future
	// note that caching happens only if verification is successful
	replayAttackCache.Add(iatInClaims, string(claimsString))
	serveHttpResponse(start, response, lg, http.StatusOK, "info", "", traceID, "", resp)
}

// validateHeader - validate JWT header
// check if expected key-values exist
func validateHeader(start time.Time, w http.ResponseWriter, traceID, clientIP, j string) (string, map[string]interface{}, error) {
	var x5u string
	s := strings.Split(j, ".")
	// s[0] is the encoded header
	h, err := base64Decode(s[0])
	if err != nil {
		lg := kitlog.With(glogger, "type", "jwtHeader", "clientIP", clientIP, "module", "validateHeader", "error", fmt.Sprintf("%v - unable to base64 url decode header part of JWT", err))
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4150", nil)
		return "", nil, err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(h, &m); err != nil {
		lg := kitlog.With(glogger, "type", "jwtHeader", "clientIP", clientIP, "module", "validateHeader", "error", fmt.Sprintf("%v - unable to unmarshal decoded header to map[string]interface{}", err))
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4151", nil)
		return "", nil, err
	}
	if len(m) != 4 {
		// not the expected number of fields in header
		lg := kitlog.With(glogger, "type", "jwtHeader", "clientIP", clientIP, "module", "validateHeader", "error", "decoded header does not have the expected number of fields (4)")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4132", nil)
		return "", nil, fmt.Errorf("decoded header does not have the expected number of fields (4)")
	}
	// err == nil
	if !reflect.ValueOf(m["alg"]).IsValid() || !reflect.ValueOf(m["ppt"]).IsValid() || !reflect.ValueOf(m["typ"]).IsValid() || !reflect.ValueOf(m["x5u"]).IsValid() {
		lg := kitlog.With(glogger, "type", "jwtHeader", "clientIP", clientIP, "module", "validateHeader", "error", "one or more of the required fields missing in JWT header")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4133", nil)
		return "", nil, fmt.Errorf("one or more of the required fields missing in JWT header")
	}

	// alg ...
	switch reflect.TypeOf(m["alg"]).Kind() {
	case reflect.String:
		alg := reflect.ValueOf(m["alg"]).String()
		if alg != "ES256" {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader", "error", "alg field value in JWT header is not \"ES256\"")
			serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4134", nil)
			return "", nil, fmt.Errorf("alg field value in JWT header is not \"ES256\"")
		}
	default:
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader", "error", "alg field in JWT header is not a string")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4135", nil)
		return "", nil, fmt.Errorf("alg field value in JWT header is not a string")
	}

	// ppt ...
	switch reflect.TypeOf(m["ppt"]).Kind() {
	case reflect.String:
		ppt := reflect.ValueOf(m["ppt"]).String()
		if ppt != "shaken" {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader", "error", "ppt field value in JWT header is not \"shaken\"")
			serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4136", nil)
			return "", nil, fmt.Errorf("ppt field value in JWT header is not \"shaken\"")
		}
	default:
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader", "error", "ppt field value in JWT header is not a string")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4137", nil)
		return "", nil, fmt.Errorf("ppt field value in JWT header is not a string")
	}

	// typ ...
	switch reflect.TypeOf(m["typ"]).Kind() {
	case reflect.String:
		typ := reflect.ValueOf(m["typ"]).String()
		if typ != "passport" {
			lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader", "error", "typ field value in JWT header is not \"passport\"")
			serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4138", nil)
			return "", nil, fmt.Errorf("typ field value in JWT header is not \"passport\"")
		}
	default:
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader", "error", "typ field value in JWT header is not a string")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4139", nil)
		return "", nil, fmt.Errorf("typ field value in JWT header is not a string")
	}

	// x5u ...
	switch reflect.TypeOf(m["x5u"]).Kind() {
	case reflect.String:
		x5u = reflect.ValueOf(m["x5u"]).String()
	default:
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateHeader", "error", "x5u field value in JWT header is not a string")
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4140", nil)
		return "", nil, fmt.Errorf("x5u field value in JWT header is not a string")
	}

	return x5u, m, nil
}

// validateClaims - validate JWT claims
// check if expected key-values exist
func validateClaims(start time.Time, w http.ResponseWriter, traceID, clientIP, j, oTN string, dTNs []string, iat, t int64) (map[string]interface{}, int64, error) {
	s := strings.Split(j, ".")
	// s[0] is the encoded claims
	c, err := base64Decode(s[1])
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims", "error", fmt.Sprintf("%v - unable to base64 url decode claims part of JWT", err))
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4152", nil)
		return nil, 0, err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(c, &m); err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims", "error", fmt.Sprintf("%v - unable to unmarshal decoded claims to map[string]interface{}", err))
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4153", nil)
		return nil, 0, err
	}
	//origTNInClaims, iatInClaims, destTNsInClaims, err := validatePayload(w, m, traceID, clientIP)
	orderedMap, origTNInClaims, iatInClaims, destTNsInClaims, _, errCode, err := validatePayload(m, traceID, clientIP)
	if err != nil {
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims", "error", err)
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", errCode, nil)
		return nil, 0, err
	}
	// validate orig TN
	if origTNInClaims != oTN {
		es := fmt.Sprintf("orig TN %v in request payload does not match orig TN in JWT claims (%+v)", oTN, m)
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims", "error", es)
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4154", nil)
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
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims", "error", es)
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4155", nil)
		return nil, 0, fmt.Errorf("%v", es)
	}
	// iat in JWT validation
	if (t > (iatInClaims + configuration.ConfigurationInstance().ValidIatPeriod)) {
		es := fmt.Sprintf("iat value (%v seconds) in JWT claims indicates stale date", iatInClaims)
		lg := kitlog.With(glogger, "type", "requestPayload", "clientIP", clientIP, "module", "validateClaims", "error", es)
		serveHttpResponse(start, w, lg, http.StatusBadRequest, "error", traceID, "verificationResponse", "VESPER-4167", nil)
		return nil, 0, fmt.Errorf("%v", es)
	}
	return orderedMap, iatInClaims, nil
}
