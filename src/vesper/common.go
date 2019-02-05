// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"fmt"
	"time"
	"net/http"
	"encoding/json"
	"strings"
	"reflect"
	"vesper/errorhandler"
	"vesper/stats"
	kitlog "github.com/go-kit/kit/log"
)

func validatePayload(r map[string]interface{}, traceID, clientIP string) (map[string]interface{}, string, int64, []string, string, string, error) {
	var attest, origID, origTN string
	var iat int64
	var destTNs []string
	orderedMap := make(map[string]interface{})		// this is a copy of the map passed in input except the keys are ordered
	
	if !reflect.ValueOf(r["attest"]).IsValid() || !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["origid"]).IsValid() {
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4003", fmt.Errorf("one or more of the require fields missing in request payload")
	}
	// request payload should not contain more than the expected fields
	if len(r) != 5 {
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4004", fmt.Errorf("request payload has more than expected fields")
	}
	
	// attest ...
	switch reflect.TypeOf(r["attest"]).Kind() {
	case reflect.String:
		attest = reflect.ValueOf(r["attest"]).String()
		if len(strings.TrimSpace(attest)) == 0 {
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4005", fmt.Errorf("attest field in request payload is an empty string")
		}
		switch attest {
		case "A", "B", "C":
			// as per SHAKEN SPEC
		default :
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4006", fmt.Errorf("attest field in request payload is not as per SHAKEN spec")
		}
		orderedMap["attest"] = r["attest"]
	default:
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4007", fmt.Errorf("attest field in request payload MUST be a string")
	}
	
	// dest ...
	switch reflect.TypeOf(r["dest"]).Kind() {
	case reflect.Map:
		destKeys := reflect.ValueOf(r["dest"]).MapKeys()
		switch {
		case len(destKeys) == 0 :
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4018", fmt.Errorf("dest in request payload is an empty object")
		case len(destKeys) > 1 :
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4019", fmt.Errorf("dest in request payload should contain only one field")
		default:
			// field should be "tn" only
			if destKeys[0].String() != "tn" {
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4020", fmt.Errorf("dest in request payload does not contain field \"tn\"")
			}
			// validate "tn" value is of type string and is not an empty string
			switch reflect.TypeOf(r["dest"].(map[string]interface{})["tn"]).Kind() {
			case reflect.Slice:
				// empty array object
				dt := reflect.ValueOf(r["dest"].(map[string]interface{})["tn"])
				if dt.Len() == 0 {
					return orderedMap, origTN, iat, destTNs, "", "VESPER-4021", fmt.Errorf("dest tn in request payload is an empty array")
				}
				// contains empty string
				for i := 0; i < dt.Len(); i++ {
					tn := dt.Index(i).Elem()
					if tn.Kind() != reflect.String {
						return orderedMap, origTN, iat, destTNs, "", "VESPER-4022", fmt.Errorf("one or more dest tns in request payload is not a string")
					} else {
						if len(strings.TrimSpace(tn.String())) == 0 {
							return orderedMap, origTN, iat, destTNs, "", "VESPER-4023", fmt.Errorf("one or more dest tns in request payload is an empty string")
						}
						// append desl TNs here
						destTNs = append(destTNs, tn.String())
					}
				}
			default:
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4024", fmt.Errorf("dest tn in request payload is not an array")
			}
			orderedMap["dest"] = r["dest"]
		}
	default:
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4025", fmt.Errorf("dest field in request payload MUST be a JSON object")
	}
	
	// iat ...
	switch reflect.TypeOf(r["iat"]).Kind() {
	case reflect.Float64:
		iat = int64(reflect.ValueOf(r["iat"]).Float())
		if iat <= 0 {
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4008", fmt.Errorf("iat value in request payload is <= 0")
		}
		orderedMap["iat"] = r["iat"]
	default:
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4009", fmt.Errorf("iat field in request payload MUST be a number")
	}
	
	// orig ...
	switch reflect.TypeOf(r["orig"]).Kind() {
	case reflect.Map:
		origKeys := reflect.ValueOf(r["orig"]).MapKeys()
		switch {
		case len(origKeys) == 0 :
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4012", fmt.Errorf("orig in request payload is an empty object")
		case len(origKeys) > 1 :
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4013", fmt.Errorf("orig in request payload should contain only one field")
		default:
			// field should be "tn" only
			if origKeys[0].String() != "tn" {
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4014", fmt.Errorf("orig in request payload does not contain field \"tn\"")
			}
			// validate "tn" value is of type string and is not an empty string
			_, ok := r["orig"].(map[string]interface{})["tn"].(string)
			if !ok {
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4015", fmt.Errorf("orig tn in request payload is not of type string")
			}
			origTN = r["orig"].(map[string]interface{})["tn"].(string)
			if len(strings.TrimSpace(origTN)) == 0 {
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4016", fmt.Errorf("orig tn in request payload is an empty string")
			}
		}
		orderedMap["orig"] = r["orig"]
	default:
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4017", fmt.Errorf("orig field in request payload MUST be a JSON object")
	}
	
	// origid ...
	switch reflect.TypeOf(r["origid"]).Kind() {
	case reflect.String:
		origID = reflect.ValueOf(r["origid"]).String()
		if len(strings.TrimSpace(origID)) == 0 {
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4010", fmt.Errorf("origid field in request payload is an empty string")
		}
		orderedMap["origid"] = r["origid"]
	default:
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4011", fmt.Errorf("origid field in request payload MUST be a string")
	}
	
	return orderedMap, origTN, iat, destTNs, origID, "", nil
}

func serveHttpResponse(s time.Time, w http.ResponseWriter, l kitlog.Logger, httpCode int, level, traceID, action, eCode string, data interface{}) {
	resp := make(map[string]interface{})
	w.WriteHeader(httpCode)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	} else {
		if len(action) > 0 && len(eCode) > 0 {
			resp[action] = make(map[string]interface{})
			resp[action].(map[string]interface{})["code"] = eCode
			resp[action].(map[string]interface{})["message"] = errorhandler.ReasonString[eCode]
			json.NewEncoder(w).Encode(resp)
		}
	}
	t := int64(time.Since(s).Seconds()*1000)
	stats.UpdateApiProcessingTime(t)
	lg := kitlog.With(
		l,
		"code", level,
		"traceID", traceID,
		"httpResponseCode", httpCode, 
		"httpErrorResponseBody", resp,
		"apiProcessingTimeInMilliSeconds", t,
	)
	lg.Log()
}
