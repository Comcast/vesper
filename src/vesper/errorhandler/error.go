package errorhandler

import (
	"strings"
	"encoding/json"
)

// ErrorBlob -- This is a standard error object
type ErrorBlob struct {
	ReasonCode string `json:"code"`
	ReasonString string `json:"message"`
}

// ErrorResponse -- for HTTP response codes used for more than one anomaly
type ErrorResponse struct {
	Error ErrorBlob `json:"error"`
}

// method that encodes error object into json
func JsonEncode(c, s string) []byte {
	var b []byte
	if len(strings.TrimSpace(c)) == 0 && len(strings.TrimSpace(s)) == 0 {
		return b
	}
	jsonErr := ErrorResponse{Error : ErrorBlob{ReasonCode: c, ReasonString: s}}
	b, _ = json.Marshal(jsonErr)
	return b
}
