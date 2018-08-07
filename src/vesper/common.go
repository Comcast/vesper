// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
  "fmt"
	"strings"
	"reflect"
)

func validatePayload(r map[string]interface{}, traceID, clientIP string) (map[string]interface{}, string, int64, []string, string, string, error) {
	var attest, origID, origTN string
	var iat int64
	var destTNs []string
	orderedMap := make(map[string]interface{})		// this is a copy of the map passed in input except the keys are ordered
	
	if !reflect.ValueOf(r["attest"]).IsValid() || !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["origid"]).IsValid() {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4003, ReasonString=one or more of the require fields missing in request payload (%+v)", traceID, clientIP, r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4003", fmt.Errorf("one or more of the require fields missing in request payload")
	}
	// request payload should not contain more than the expected fields
	if len(r) != 5 {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4004, ReasonString=request payload (%+v) has more than expected fields", traceID, clientIP, r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4004", fmt.Errorf("request payload has more than expected fields")
	}
	
	// attest ...
	switch reflect.TypeOf(r["attest"]).Kind() {
	case reflect.String:
		attest = reflect.ValueOf(r["attest"]).String()
		if len(strings.TrimSpace(attest)) == 0 {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4005, ReasonString=attest field in request payload (%+v) is an empty string", traceID, clientIP, r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4005", fmt.Errorf("attest field in request payload is an empty string")
		}
		switch attest {
		case "A", "B", "C":
			// as per SHAKEN SPEC
		default :
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4006, ReasonString=attest value in request payload (%+v) is not as per SHAKEN spec", traceID, clientIP, r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4006", fmt.Errorf("attest field in request payload is not as per SHAKEN spec")
		}
		orderedMap["attest"] = r["attest"]
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4007, ReasonString=attest field in request payload (%+v) MUST be a string", traceID, clientIP, r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4007", fmt.Errorf("attest field in request payload MUST be a string")
	}
	
	// dest ...
	switch reflect.TypeOf(r["dest"]).Kind() {
	case reflect.Map:
		destKeys := reflect.ValueOf(r["dest"]).MapKeys()
		switch {
		case len(destKeys) == 0 :
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4018, ReasonString=dest in request payload (%+v) is an empty object", traceID, clientIP, r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4018", fmt.Errorf("dest in request payload is an empty object")
		case len(destKeys) > 1 :
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4019, ReasonString=dest in request payload (%+v) should contain only one field", traceID, clientIP, r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4019", fmt.Errorf("dest in request payload should contain only one field")
		default:
			// field should be "tn" only
			if destKeys[0].String() != "tn" {
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4020, ReasonString=dest in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4020", fmt.Errorf("dest in request payload does not contain field \"tn\"")
			}
			// validate "tn" value is of type string and is not an empty string
			switch reflect.TypeOf(r["dest"].(map[string]interface{})["tn"]).Kind() {
			case reflect.Slice:
				// empty array object
				dt := reflect.ValueOf(r["dest"].(map[string]interface{})["tn"])
				if dt.Len() == 0 {
				  logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4021, ReasonString=dest tn in request payload (%+v) is an empty array", traceID, clientIP, r)
				  return orderedMap, origTN, iat, destTNs, "", "VESPER-4021", fmt.Errorf("dest tn in request payload is an empty array")
				}
				// contains empty string
				for i := 0; i < dt.Len(); i++ {
				  tn := dt.Index(i).Elem()
				  if tn.Kind() != reflect.String {
				    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4022, ReasonString=one or more dest tns in request payload (%+v) is not a string", traceID, clientIP, r)
				    return orderedMap, origTN, iat, destTNs, "", "VESPER-4022", fmt.Errorf("one or more dest tns in request payload is not a string")
				  } else {
				    if len(strings.TrimSpace(tn.String())) == 0 {
				      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4023, ReasonString=one or more dest tns in request payload (%+v) is an empty string", traceID, clientIP, r)
				      return orderedMap, origTN, iat, destTNs, "", "VESPER-4023", fmt.Errorf("one or more dest tns in request payload is an empty string")
				    }
				    // append desl TNs here
				    destTNs = append(destTNs, tn.String())
				  }
				}
			default:
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4024, ReasonString=dest tn in request payload (%+v) is not an array", traceID, clientIP, r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4024", fmt.Errorf("dest tn in request payload is not an array")
			}
			orderedMap["dest"] = r["dest"]
		}
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4025, ReasonString=dest field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4025", fmt.Errorf("dest field in request payload MUST be a JSON object")
	}
	
	// iat ...
	switch reflect.TypeOf(r["iat"]).Kind() {
	case reflect.Float64:
		iat = int64(reflect.ValueOf(r["iat"]).Float())
		if iat <= 0 {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4008, ReasonString=iat value in request payload is <= 0", traceID, clientIP, r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4008", fmt.Errorf("iat value in request payload is <= 0")
		}
		orderedMap["iat"] = r["iat"]
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4009, ReasonString=iat field in request payload (%+v) MUST be a number", traceID, clientIP, r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4009", fmt.Errorf("iat field in request payload MUST be a number")
	}
	
	// orig ...
	switch reflect.TypeOf(r["orig"]).Kind() {
	case reflect.Map:
		origKeys := reflect.ValueOf(r["orig"]).MapKeys()
		switch {
		case len(origKeys) == 0 :
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4012, ReasonString=orig in request payload (%+v) is an empty object", traceID, clientIP, r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4012", fmt.Errorf("orig in request payload is an empty object")
		case len(origKeys) > 1 :
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4013, ReasonString=orig in request payload (%+v) should contain only one field", traceID, clientIP, r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4013", fmt.Errorf("orig in request payload should contain only one field")
		default:
			// field should be "tn" only
			if origKeys[0].String() != "tn" {
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4014, ReasonString=orig in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4014", fmt.Errorf("orig in request payload does not contain field \"tn\"")
			}
			// validate "tn" value is of type string and is not an empty string
			_, ok := r["orig"].(map[string]interface{})["tn"].(string)
			if !ok {
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4015, ReasonString=orig tn in request payload (%+v) is not of type string", traceID, clientIP, r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4015", fmt.Errorf("orig tn in request payload is not of type string")
			}
			origTN = r["orig"].(map[string]interface{})["tn"].(string)
			if len(strings.TrimSpace(origTN)) == 0 {
				logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4016, ReasonString=orig tn in request payload (%+v) is an empty string", traceID, clientIP, r)
				return orderedMap, origTN, iat, destTNs, "", "VESPER-4016", fmt.Errorf("orig tn in request payload is an empty string")
			}
		}
		orderedMap["orig"] = r["orig"]
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4017, ReasonString=orig field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4017", fmt.Errorf("orig field in request payload MUST be a JSON object")
	}
	
	// origid ...
	switch reflect.TypeOf(r["origid"]).Kind() {
	case reflect.String:
		origID = reflect.ValueOf(r["origid"]).String()
		if len(strings.TrimSpace(origID)) == 0 {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4010, ReasonString=origid field in request payload (%+v) is an empty string", traceID, clientIP, r)
			return orderedMap, origTN, iat, destTNs, "", "VESPER-4010", fmt.Errorf("origid field in request payload is an empty string")
		}
		orderedMap["origid"] = r["origid"]
	default:
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, ReasonCode=VESPER-4011, ReasonString=origid field in request payload (%+v) MUST be a string", traceID, clientIP, r)
		return orderedMap, origTN, iat, destTNs, "", "VESPER-4011", fmt.Errorf("origid field in request payload MUST be a string")
	}
	
	return orderedMap, origTN, iat, destTNs, origID, "", nil
}
