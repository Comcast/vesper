// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
  "fmt"
	"strings"
	"reflect"
)

func validatePayload(r map[string]interface{}, traceID, clientIP string) (string, uint64, []string, string, error) {
  var attest, origid, origTN string
	var iat uint64
  var destTNs []string

  if !reflect.ValueOf(r["attest"]).IsValid() || !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["origid"]).IsValid() {
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=one or more of the require fields missing in request payload (%+v)", traceID, clientIP, r);
    return origTN, iat, destTNs, "VESPER-0003", fmt.Errorf("one or more of the require fields missing in request payload")
  }
  // request payload should not contain more than the expected fields
  if len(r) != 5 {
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=request payload (%+v) has more than expected fields", traceID, clientIP, r);
    return origTN, iat, destTNs, "VESPER-0004", fmt.Errorf("request payload has more than expected fields")
  }

	// lexicographical order check
	var pk string
	c := 0
	for k, _ := range r {
		if c++ > 0 && k < pk {
			logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=keys in request payload (%+v) is not lexicographically ordered", traceID, clientIP, r);
			return origTN, iat, destTNs, "VESPER-0026", fmt.Errorf("%v lexically bytewise less than %v, in request payload")
		}
		pk = k	// save for next iteration
	}	
	
  // attest ...
  switch reflect.TypeOf(r["attest"]).Kind() {
  case reflect.String:
    attest = reflect.ValueOf(r["attest"]).String()
    if len(strings.TrimSpace(attest)) == 0 {
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=attest field in request payload (%+v) is an empty string", traceID, clientIP, r);
      return origTN, iat, destTNs, "VESPER-0005", fmt.Errorf("attest field in request payload is an empty string")
    }
    switch attest {
    case "A", "B", "C":
      // as per SHAKEN SPEC
    default :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=attest value in request payload (%+v) is not as per SHAKEN spec", traceID, clientIP, r);
      return origTN, iat, destTNs, "VESPER-0006", fmt.Errorf("attest field in request payload is not as per SHAKEN spec")
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=attest field in request payload (%+v) MUST be a string", traceID, clientIP, r);
    return origTN, iat, destTNs, "VESPER-0007", fmt.Errorf("attest field in request payload MUST be a string")
  }

  // iat ...
  switch reflect.TypeOf(r["iat"]).Kind() {
  case reflect.Float64:
    iat = uint64(reflect.ValueOf(r["iat"]).Float())
    if iat == 0 {
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=iat value in request payload is 0", traceID, clientIP, r);
      return origTN, iat, destTNs, "VESPER-0008", fmt.Errorf("iat value in request payload is 0")
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=iat field in request payload (%+v) MUST be a number", traceID, clientIP, r);
    return origTN, iat, destTNs, "VESPER-0009", fmt.Errorf("iat field in request payload MUST be a number")
  }

  // origid ...
  switch reflect.TypeOf(r["origid"]).Kind() {
  case reflect.String:
    origid = reflect.ValueOf(r["origid"]).String()
    if len(strings.TrimSpace(origid)) == 0 {
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=origid field in request payload (%+v) is an empty string", traceID, clientIP, r);
      return origTN, iat, destTNs, "VESPER-0010", fmt.Errorf("origid field in request payload is an empty string")
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=origid field in request payload (%+v) MUST be a string", traceID, clientIP, r);
    return origTN, iat, destTNs, "VESPER-0011", fmt.Errorf("origid field in request payload MUST be a string")
  }

  // orig ...
  switch reflect.TypeOf(r["orig"]).Kind() {
  case reflect.Map:
    origKeys := reflect.ValueOf(r["orig"]).MapKeys()
    switch {
    case len(origKeys) == 0 :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig in request payload (%+v) is an empty object", traceID, clientIP, r);
      return origTN, iat, destTNs, "VESPER-0012", fmt.Errorf("orig in request payload is an empty object")
    case len(origKeys) > 1 :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig in request payload (%+v) should contain only one field", traceID, clientIP, r);
      return origTN, iat, destTNs, "VESPER-0013", fmt.Errorf("orig in request payload should contain only one field")
    default:
      // field should be "tn" only
      if origKeys[0].String() != "tn" {
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r);
        return origTN, iat, destTNs, "VESPER-0014", fmt.Errorf("orig in request payload does not contain field \"tn\"")
      }
      // validate "tn" value is of type string and is not an empty string
      _, ok := r["orig"].(map[string]interface{})["tn"].(string)
      if !ok {
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig tn in request payload (%+v) is not of type string", traceID, clientIP, r);
        return origTN, iat, destTNs, "VESPER-0015", fmt.Errorf("orig tn in request payload is not of type string")
      }
      origTN = r["orig"].(map[string]interface{})["tn"].(string)
      if len(strings.TrimSpace(origTN)) == 0 {
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig tn in request payload (%+v) is an empty string", traceID, clientIP, r);
        return origTN, iat, destTNs, "VESPER-0016", fmt.Errorf("orig tn in request payload is an empty string")
      }
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r);
    return origTN, iat, destTNs, "VESPER-0017", fmt.Errorf("orig field in request payload MUST be a JSON object")
  }

  // dest ...
  switch reflect.TypeOf(r["dest"]).Kind() {
  case reflect.Map:
    destKeys := reflect.ValueOf(r["dest"]).MapKeys()
    switch {
    case len(destKeys) == 0 :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest in request payload (%+v) is an empty object", traceID, clientIP, r);
      return origTN, iat, destTNs, "VESPER-0018", fmt.Errorf("dest in request payload is an empty object")
    case len(destKeys) > 1 :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest in request payload (%+v) should contain only one field", traceID, clientIP, r);
      return origTN, iat, destTNs, "VESPER-0019", fmt.Errorf("dest in request payload should contain only one field")
    default:
      // field should be "tn" only
      if destKeys[0].String() != "tn" {
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r);
        return origTN, iat, destTNs, "VESPER-0020", fmt.Errorf("dest in request payload does not contain field \"tn\"")
      }
      // validate "tn" value is of type string and is not an empty string
      switch reflect.TypeOf(r["dest"].(map[string]interface{})["tn"]).Kind() {
      case reflect.Slice:
        // empty array object
        dt := reflect.ValueOf(r["dest"].(map[string]interface{})["tn"])
        if dt.Len() == 0 {
          logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest tn in request payload (%+v) is an empty array", traceID, clientIP, r);
          return origTN, iat, destTNs, "VESPER-0021", fmt.Errorf("dest tn in request payload is an empty array")
        }
        // contains empty string
        for i := 0; i < dt.Len(); i++ {
          tn := dt.Index(i).Elem()
          if tn.Kind() != reflect.String {
            logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=one or more dest tns in request payload (%+v) is not a string", traceID, clientIP, r);
            return origTN, iat, destTNs, "VESPER-0022", fmt.Errorf("one or more dest tns in request payload is not a string")
          } else {
            if len(strings.TrimSpace(tn.String())) == 0 {
              logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=one or more dest tns in request payload (%+v) is an empty string", traceID, clientIP, r);
              return origTN, iat, destTNs, "VESPER-0023", fmt.Errorf("one or more dest tns in request payload is an empty string")
            }
            // append desl TNs here
            destTNs = append(destTNs, tn.String())
          }
        }
      default:
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest tn in request payload (%+v) is not an array", traceID, clientIP, r);
        return origTN, iat, destTNs, "VESPER-0024", fmt.Errorf("dest tn in request payload is not an array")
      }
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r);
    return origTN, iat, destTNs, "VESPER-0025", fmt.Errorf("dest field in request payload MUST be a JSON object")
  }
  return origTN, iat, destTNs, "", nil
}
