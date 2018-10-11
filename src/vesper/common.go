// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"fmt"
	"time"
	"net/http"
	"strings"
	"reflect"
	"vesper/errorhandler"
	kitlog "github.com/go-kit/kit/log"
)

func validatePayload(r map[string]interface{}, traceID, clientIP string) (map[string]interface{}, string, int64, []string, string, string, error) {
	var attest, origID, origTN string
	var iat int64
	var destTNs []string
	orderedMap := make(map[string]interface{})		// this is a copy of the map passed in input except the keys are ordered
	
	if !reflect.ValueOf(r["attest"]).IsValid() || !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["origid"]).IsValid() {
		logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4003", "reasonString", "one or more of the require fields missing in request payload", "requestPayload", r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4003", fmt.Errorf("one or more of the require fields missing in request payload")
	}
	// request payload should not contain more than the expected fields
	if len(r) != 5 {
		logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4004", "reasonString", "request payload has more than expected fields", "requestPayload", r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4004", fmt.Errorf("request payload has more than expected fields")
	}
	
	// attest ...
	switch reflect.TypeOf(r["attest"]).Kind() {
	case reflect.String:
		attest = reflect.ValueOf(r["attest"]).String()
		if len(strings.TrimSpace(attest)) == 0 {
			logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4005", "reasonString", "attest field in request payload is an empty string", "requestPayload", r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4005", fmt.Errorf("attest field in request payload is an empty string")
		}
		switch attest {
		case "A", "B", "C":
			// as per SHAKEN SPEC
		default :
			logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4006", "reasonString", "attest field in request payload is not as per SHAKEN spec", "requestPayload", r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4006", fmt.Errorf("attest field in request payload is not as per SHAKEN spec")
		}
		orderedMap["attest"] = r["attest"]
	default:
		logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4007", "reasonString", "attest field in request payload MUST be a string", "requestPayload", r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4007", fmt.Errorf("attest field in request payload MUST be a string")
	}
	
	// dest ...
	switch reflect.TypeOf(r["dest"]).Kind() {
	case reflect.Map:
		destKeys := reflect.ValueOf(r["dest"]).MapKeys()
		switch {
		case len(destKeys) == 0 :
			logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4018", "reasonString", "dest in request payload is an empty object", "requestPayload", r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4018", fmt.Errorf("dest in request payload is an empty object")
		case len(destKeys) > 1 :
			logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4019", "reasonString", "dest in request payload should contain only one field", "requestPayload", r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4019", fmt.Errorf("dest in request payload should contain only one field")
		default:
			// field should be "tn" only
			if destKeys[0].String() != "tn" {
				logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4020", "reasonString", "dest in request payload does not contain field \"tn\"", "requestPayload", r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4020", fmt.Errorf("dest in request payload does not contain field \"tn\"")
			}
			// validate "tn" value is of type string and is not an empty string
			switch reflect.TypeOf(r["dest"].(map[string]interface{})["tn"]).Kind() {
			case reflect.Slice:
				// empty array object
				dt := reflect.ValueOf(r["dest"].(map[string]interface{})["tn"])
				if dt.Len() == 0 {
					logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4021", "reasonString", "dest tn in request payload is an empty array", "requestPayload", r)
					return orderedMap, origTN, iat, destTNs, "", "VESPER-4021", fmt.Errorf("dest tn in request payload is an empty array")
				}
				// contains empty string
				for i := 0; i < dt.Len(); i++ {
					tn := dt.Index(i).Elem()
					if tn.Kind() != reflect.String {
						logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4022", "reasonString", "one or more dest tns in request payload is not a string", "requestPayload", r)
						return orderedMap, origTN, iat, destTNs, "", "VESPER-4022", fmt.Errorf("one or more dest tns in request payload is not a string")
					} else {
						if len(strings.TrimSpace(tn.String())) == 0 {
							logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4023", "reasonString", "one or more dest tns in request payload is an empty string", "requestPayload", r)
							return orderedMap, origTN, iat, destTNs, "", "VESPER-4023", fmt.Errorf("one or more dest tns in request payload is an empty string")
						}
						// append desl TNs here
						destTNs = append(destTNs, tn.String())
					}
				}
			default:
				logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4024", "reasonString", "dest tn in request payload is not an array", "requestPayload", r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4024", fmt.Errorf("dest tn in request payload is not an array")
			}
			orderedMap["dest"] = r["dest"]
		}
	default:
		logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4025", "reasonString", "dest field in request payload MUST be a JSON object", "requestPayload", r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4025", fmt.Errorf("dest field in request payload MUST be a JSON object")
	}
	
	// iat ...
	switch reflect.TypeOf(r["iat"]).Kind() {
	case reflect.Float64:
		iat = int64(reflect.ValueOf(r["iat"]).Float())
		if iat <= 0 {
			logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4008", "reasonString", "iat value in request payload is <= 0", "requestPayload", r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4008", fmt.Errorf("iat value in request payload is <= 0")
		}
		orderedMap["iat"] = r["iat"]
	default:
		logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4009", "reasonString", "iat field in request payload MUST be a number", "requestPayload", r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4009", fmt.Errorf("iat field in request payload MUST be a number")
	}
	
	// orig ...
	switch reflect.TypeOf(r["orig"]).Kind() {
	case reflect.Map:
		origKeys := reflect.ValueOf(r["orig"]).MapKeys()
		switch {
		case len(origKeys) == 0 :
			logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4012", "reasonString", "orig in request payload is an empty object", "requestPayload", r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4012", fmt.Errorf("orig in request payload is an empty object")
		case len(origKeys) > 1 :
			logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4013", "reasonString", "orig in request payload should contain only one field", "requestPayload", r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4013", fmt.Errorf("orig in request payload should contain only one field")
		default:
			// field should be "tn" only
			if origKeys[0].String() != "tn" {
				logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4014", "reasonString", "orig in request payload does not contain field \"tn\"", "requestPayload", r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4014", fmt.Errorf("orig in request payload does not contain field \"tn\"")
			}
			// validate "tn" value is of type string and is not an empty string
			_, ok := r["orig"].(map[string]interface{})["tn"].(string)
			if !ok {
				logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4015", "reasonString", "orig tn in request payload is not of type string", "requestPayload", r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4015", fmt.Errorf("orig tn in request payload is not of type string")
			}
			origTN = r["orig"].(map[string]interface{})["tn"].(string)
			if len(strings.TrimSpace(origTN)) == 0 {
				logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4016", "reasonString", "orig tn in request payload is an empty string", "requestPayload", r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4016", fmt.Errorf("orig tn in request payload is an empty string")
			}
		}
		orderedMap["orig"] = r["orig"]
	default:
		logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4017", "reasonString", "orig field in request payload MUST be a JSON object", "requestPayload", r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4017", fmt.Errorf("orig field in request payload MUST be a JSON object")
	}
	
	// origid ...
	switch reflect.TypeOf(r["origid"]).Kind() {
	case reflect.String:
		origID = reflect.ValueOf(r["origid"]).String()
		if len(strings.TrimSpace(origID)) == 0 {
			logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4010", "reasonString", "origid field in request payload is an empty string", "requestPayload", r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4010", fmt.Errorf("origid field in request payload is an empty string")
		}
		orderedMap["origid"] = r["origid"]
	default:
		logError("type", "requestPayload", "traceID", traceID, "clientIP", clientIP, "module", "validatePayload", "reasonCode", "VESPER-4011", "reasonString", "origid field in request payload MUST be a string", "requestPayload", r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4011", fmt.Errorf("origid field in request payload MUST be a string")
	}
	
	return orderedMap, origTN, iat, destTNs, origID, "", nil
}

func serveHttpResponse(s time.Time, w http.ResponseWriter, l kitlog.Logger, httpCode int, level, traceID, eCode, eString string) {
	jsonErr := errorhandler.JsonEncode(eCode, eString)
	lg := kitlog.With(
		l,
		"code", level,
		"traceID", traceID,
		"httpResponseCode", httpCode, 
		"httpErrorResponseBody", string(jsonErr),
		"apiProcessingTime", fmt.Sprintf("%v", time.Since(s)),
	)
	lg.Log()
	w.WriteHeader(httpCode)
	if len(jsonErr) > 0 {
		w.Write(jsonErr)
	}
}
