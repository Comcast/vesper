// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
  "fmt"
	"encoding/json"
	"net/http"
	"strings"
	"reflect"
)

func validatePayload(w http.ResponseWriter, r map[string]interface{}, traceID, clientIP string) (string, uint64, []string, error) {
  var attest, origid, origTN string
	var iat uint64
  var destTNs []string

  if !reflect.ValueOf(r["attest"]).IsValid() || !reflect.ValueOf(r["dest"]).IsValid() || !reflect.ValueOf(r["iat"]).IsValid() || !reflect.ValueOf(r["orig"]).IsValid() || !reflect.ValueOf(r["origid"]).IsValid() {
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=one or more of the require fields missing in request payload (%+v)", traceID, clientIP, r);
    w.WriteHeader(http.StatusBadRequest)
    jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0003", Message: "one or more of the require fields missing in request payload"}}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jsonErr)
    return origTN, iat, destTNs, fmt.Errorf("one or more of the require fields missing in request payload")
  }
  // request payload should not contain more than the expected fields
  if len(r) != 5 {
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=request payload (%+v) has more than expected fields", traceID, clientIP, r);
    w.WriteHeader(http.StatusBadRequest)
    jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0004", Message: "request payload has more than expected fields"}}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jsonErr)
    return origTN, iat, destTNs, fmt.Errorf("request payload has more than expected fields")
  }

  // attest ...
  switch reflect.TypeOf(r["attest"]).Kind() {
  case reflect.String:
    attest = reflect.ValueOf(r["attest"]).String()
    if len(strings.TrimSpace(attest)) == 0 {
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=attest field in request payload (%+v) is an empty string", traceID, clientIP, r);
      w.WriteHeader(http.StatusBadRequest)
      jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0005", Message: "attest field in request payload is an empty string"}}
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(jsonErr)
      return origTN, iat, destTNs, fmt.Errorf("attest field in request payload is an empty string")
    }
    switch attest {
    case "A", "B", "C":
      // as per SHAKEN SPEC
    default :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=attest value in request payload (%+v) is not as per SHAKEN spec", traceID, clientIP, r);
      w.WriteHeader(http.StatusBadRequest)
      jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0006", Message: "attest field in request payload is not as per SHAKEN spec"}}
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(jsonErr)
      return origTN, iat, destTNs, fmt.Errorf("attest field in request payload is not as per SHAKEN spec")
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=attest field in request payload (%+v) MUST be a string", traceID, clientIP, r);
    w.WriteHeader(http.StatusBadRequest)
    jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0007", Message: "attest field in request payload MUST be a string"}}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jsonErr)
    return origTN, iat, destTNs, fmt.Errorf("attest field in request payload MUST be a string")
  }

  // iat ...
  switch reflect.TypeOf(r["iat"]).Kind() {
  case reflect.Float64:
    iat = uint64(reflect.ValueOf(r["iat"]).Float())
    if iat == 0 {
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=iat value in request payload is 0", traceID, clientIP, r);
      w.WriteHeader(http.StatusBadRequest)
      jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0008", Message: "iat value in request payload is 0"}}
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(jsonErr)
      return origTN, iat, destTNs, fmt.Errorf("iat value in request payload is 0")
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=iat field in request payload (%+v) MUST be a number", traceID, clientIP, r);
    w.WriteHeader(http.StatusBadRequest)
    jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0009", Message: "iat field in request payload MUST be a number"}}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jsonErr)
    return origTN, iat, destTNs, fmt.Errorf("iat field in request payload MUST be a number")
  }

  // origid ...
  switch reflect.TypeOf(r["origid"]).Kind() {
  case reflect.String:
    origid = reflect.ValueOf(r["origid"]).String()
    if len(strings.TrimSpace(origid)) == 0 {
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=origid field in request payload (%+v) is an empty string", traceID, clientIP, r);
      w.WriteHeader(http.StatusBadRequest)
      jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0010", Message: "origid field in request payload is an empty string"}}
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(jsonErr)
      return origTN, iat, destTNs, fmt.Errorf("origid field in request payload is an empty string")
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=origid field in request payload (%+v) MUST be a string", traceID, clientIP, r);
    w.WriteHeader(http.StatusBadRequest)
    jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0011", Message: "origid field in request payload MUST be a string"}}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jsonErr)
    return origTN, iat, destTNs, fmt.Errorf("origid field in request payload MUST be a string")
  }

  // orig ...
  switch reflect.TypeOf(r["orig"]).Kind() {
  case reflect.Map:
    origKeys := reflect.ValueOf(r["orig"]).MapKeys()
    switch {
    case len(origKeys) == 0 :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig in request payload (%+v) is an empty object", traceID, clientIP, r);
      w.WriteHeader(http.StatusBadRequest)
      jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0012", Message: "orig in request payload is an empty object"}}
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(jsonErr)
      return origTN, iat, destTNs, fmt.Errorf("orig in request payload is an empty object")
    case len(origKeys) > 1 :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig in request payload (%+v) should contain only one field", traceID, clientIP, r);
      w.WriteHeader(http.StatusBadRequest)
      jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0013", Message: "orig in request payload should contain only one field"}}
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(jsonErr)
      return origTN, iat, destTNs, fmt.Errorf("orig in request payload should contain only one field")
    default:
      // field should be "tn" only
      if origKeys[0].String() != "tn" {
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r);
        w.WriteHeader(http.StatusBadRequest)
        jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0014", Message: "orig in request payload does not contain field \"tn\""}}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(jsonErr)
        return origTN, iat, destTNs, fmt.Errorf("orig in request payload does not contain field \"tn\"")
      }
      // validate "tn" value is of type string and is not an empty string
      _, ok := r["orig"].(map[string]interface{})["tn"].(string)
      if !ok {
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig tn in request payload (%+v) is not of type string", traceID, clientIP, r);
        w.WriteHeader(http.StatusBadRequest)
        jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0015", Message: "orig tn in request payload is not of type string"}}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(jsonErr)
        return origTN, iat, destTNs, fmt.Errorf("orig tn in request payload is not of type string")
      }
      origTN = r["orig"].(map[string]interface{})["tn"].(string)
      if len(strings.TrimSpace(origTN)) == 0 {
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig tn in request payload (%+v) is an empty string", traceID, clientIP, r);
        w.WriteHeader(http.StatusBadRequest)
        jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0016", Message: "orig tn in request payload is an empty string"}}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(jsonErr)
        return origTN, iat, destTNs, fmt.Errorf("orig tn in request payload is an empty string")
      }
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=orig field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r);
    w.WriteHeader(http.StatusBadRequest)
    jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0017", Message: "orig field in request payload MUST be a JSON object"}}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jsonErr)
    return origTN, iat, destTNs, fmt.Errorf("orig field in request payload MUST be a JSON object")
  }

  // dest ...
  switch reflect.TypeOf(r["dest"]).Kind() {
  case reflect.Map:
    destKeys := reflect.ValueOf(r["dest"]).MapKeys()
    switch {
    case len(destKeys) == 0 :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest in request payload (%+v) is an empty object", traceID, clientIP, r);
      w.WriteHeader(http.StatusBadRequest)
      jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0018", Message: "dest in request payload is an empty object"}}
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(jsonErr)
      return origTN, iat, destTNs, fmt.Errorf("dest in request payload is an empty object")
    case len(destKeys) > 1 :
      logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest in request payload (%+v) should contain only one field", traceID, clientIP, r);
      w.WriteHeader(http.StatusBadRequest)
      jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0019", Message: "dest in request payload should contain only one field"}}
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(jsonErr)
      return origTN, iat, destTNs, fmt.Errorf("dest in request payload should contain only one field")
    default:
      // field should be "tn" only
      if destKeys[0].String() != "tn" {
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest in request payload (%+v) does not contain field \"tn\"", traceID, clientIP, r);
        w.WriteHeader(http.StatusBadRequest)
        jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0020", Message: "dest in request payload does not contain field \"tn\""}}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(jsonErr)
        return origTN, iat, destTNs, fmt.Errorf("dest in request payload does not contain field \"tn\"")
      }
      // validate "tn" value is of type string and is not an empty string
      switch reflect.TypeOf(r["dest"].(map[string]interface{})["tn"]).Kind() {
      case reflect.Slice:
        // empty array object
        dt := reflect.ValueOf(r["dest"].(map[string]interface{})["tn"])
        if dt.Len() == 0 {
          logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest tn in request payload (%+v) is an empty array", traceID, clientIP, r);
          w.WriteHeader(http.StatusBadRequest)
          jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0021", Message: "dest tn in request payload is an empty array"}}
          w.Header().Set("Content-Type", "application/json")
          json.NewEncoder(w).Encode(jsonErr)
          return origTN, iat, destTNs, fmt.Errorf("dest tn in request payload is an empty array")
        }
        // contains empty string
        for i := 0; i < dt.Len(); i++ {
          tn := dt.Index(i).Elem()
          if tn.Kind() != reflect.String {
            logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=one or more dest tns in request payload (%+v) is not a string", traceID, clientIP, r);
            w.WriteHeader(http.StatusBadRequest)
            jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0022", Message: "one or more dest tns in request payload is not a string"}}
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(jsonErr)
            return origTN, iat, destTNs, fmt.Errorf("one or more dest tns in request payload is not a string")
          } else {
            if len(strings.TrimSpace(tn.String())) == 0 {
              logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=one or more dest tns in request payload (%+v) is an empty string", traceID, clientIP, r);
              w.WriteHeader(http.StatusBadRequest)
              jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0023", Message: "one or more dest tns in request payload is an empty string"}}
              w.Header().Set("Content-Type", "application/json")
              json.NewEncoder(w).Encode(jsonErr)
              return origTN, iat, destTNs, fmt.Errorf("one or more dest tns in request payload is an empty string")
            }
            // append desl TNs here
            destTNs = append(destTNs, tn.String())
          }
        }
      default:
        logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest tn in request payload (%+v) is not an array", traceID, clientIP, r);
        w.WriteHeader(http.StatusBadRequest)
        jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0024", Message: "dest tn in request payload is not an array"}}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(jsonErr)
        return origTN, iat, destTNs, fmt.Errorf("dest tn in request payload is not an array")
      }
    }
  default:
    logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=validatePayload, Message=dest field in request payload (%+v) MUST be a JSON object", traceID, clientIP, r);
    w.WriteHeader(http.StatusBadRequest)
    jsonErr := ErrorResponse{Error : ErrorBlob{Code: "VESPER-0025", Message: "dest field in request payload MUST be a JSON object"}}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jsonErr)
    return origTN, iat, destTNs, fmt.Errorf("dest field in request payload MUST be a JSON object")
  }
  return origTN, iat, destTNs, nil
}
