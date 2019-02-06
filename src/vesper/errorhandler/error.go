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

var ReasonString = map[string]string {
	"VESPER-4001" : "empty request body",
	"VESPER-4002" : "Unable to parse request body",
	"VESPER-4003" : "one or more of the require fields missing in request payload",
	"VESPER-4004" : "request payload has more than expected fields",
	"VESPER-4005" : "attest field in request payload is an empty string",
	"VESPER-4006" : "attest field in request payload is not as per SHAKEN spec",
	"VESPER-4007" : "attest field in request payload MUST be a string",
	"VESPER-4008" : "iat value in request payload is 0",
	"VESPER-4009" : "iat field in request payload MUST be a number",
	"VESPER-4010" : "origid field in request payload is an empty string",
	"VESPER-4011" : "origid field in request payload MUST be a string",
	"VESPER-4012" : "orig in request payload is an empty object",
	"VESPER-4013" : "orig in request payload should contain only one field",
	"VESPER-4014" : "orig in request payload does not contain field \"tn\"",
	"VESPER-4015" : "orig tn in request payload is not of type string",
	"VESPER-4016" : "orig tn in request payload is an empty string",
	"VESPER-4017" : "orig field in request payload MUST be a JSON object",
	"VESPER-4018" : "dest in request payload is an empty object",
	"VESPER-4019" : "dest in request payload should contain only one field",
	"VESPER-4020" : "dest in request payload does not contain field \"tn\"",
	"VESPER-4021" : "dest tn in request payload is an empty array",
	"VESPER-4022" : "one or more dest tns in request payload is not a string",
	"VESPER-4023" : "one or more dest tns in request payload is an empty string",
	"VESPER-4024" : "dest tn in request payload is not an array",
	"VESPER-4025" : "dest field in request payload MUST be a JSON object",
	"VESPER-4100" : "empty request body",
	"VESPER-4102" : "Unable to parse request body",
	"VESPER-4103" : "one or more of the require fields missing in request payload",
	"VESPER-4104" : "request payload has more than expected fields",
	"VESPER-4105" : "iat value in request payload is 0",
	"VESPER-4106" : "iat field in request payload MUST be a number",
	"VESPER-4107" : "identity field in request payload is an empty string",
	"VESPER-4108" : "attest field in request payload MUST be a string",
	"VESPER-4109" : "orig in request payload is an empty object",
	"VESPER-4110" : "orig in request payload should contain only one field",
	"VESPER-4111" : "orig in request payload does not contain field \"tn\"",
	"VESPER-4112" : "orig tn in request payload is an empty array",
	"VESPER-4113" : "orig tn array contains more than one element in request payload",
	"VESPER-4114" : "one or more orig tns in request payload is not a string",
	"VESPER-4115" : "one or more orig tns in request payload is an empty string",
	"VESPER-4116" : "orig tn in request payload is not an array",
	"VESPER-4117" : "orig field in request payload MUST be a JSON object",
	"VESPER-4118" : "dest in request payload is an empty object",
	"VESPER-4119" : "dest in request payload should contain only one field",
	"VESPER-4120" : "dest in request payload does not contain field \"tn\"",
	"VESPER-4121" : "dest tn in request payload is an empty array",
	"VESPER-4122" : "one or more dest tns in request payload is not a string",
	"VESPER-4123" : "one or more dest tns in request payload is an empty string",
	"VESPER-4124" : "dest tn in request payload is not an array",
	"VESPER-4125" : "dest field in request payload MUST be a JSON object",
	"VESPER-4126" : "Identity field does not contain all the relevant parameters",
	"VESPER-4127" : "Invalid JWT format in identity field",
	"VESPER-4128" : "Invalid info parameter in identity field",
	"VESPER-4129" : "Invalid alg parameter in identity field",
	"VESPER-4130" : "Invalid ppt parameter in identity field",
	"VESPER-4131" : "x5u value in JWT header does not match info parameter in identity field",
	"VESPER-4132" : "decoded header does not have the expected number of fields (4)",
	"VESPER-4133" : "one or more of the required fields missing in JWT header",
	"VESPER-4134" : "alg field value in JWT header is not \"ES256\"",
	"VESPER-4135" : "alg field value in JWT header is not a string",
	"VESPER-4136" : "ppt field value in JWT header is not \"shaken\"",
	"VESPER-4137" : "ppt field value in JWT header is not a string",
	"VESPER-4138" : "typ field value in JWT header is not \"passport\"",
	"VESPER-4139" : "typ field value in JWT header is not a string",
	"VESPER-4140" : "x5u field value in JWT header is not a string",
	"VESPER-4150" : "unable to base64 url decode header part of JWT",
	"VESPER-4151" : "unable to unmarshal decoded JWT header",
	"VESPER-4152" : "unable to base64 url decode claims part of JWT",
	"VESPER-4153" : "unable to unmarshal decoded JWT claims",
	"VESPER-4154" : "orig TN in request payload does not match orig TN in JWT claims",
	"VESPER-4155" : "dest TNs in request payload does not match dest TNs in JWT claims",
	"VESPER-4156" : "http request to retrieve cert from sticr failed",
	"VESPER-4157" : "error encountered reading response body",
	"VESPER-4158" : "error encountered decoding cert retrieved from sticr",
	"VESPER-4159" : "error encountered when parsing decoded pem data",
	"VESPER-4160" : "certificate has expired or is not yet valid",
	"VESPER-4161" : "certificate signed by unknown authority",
	"VESPER-4162" : "certificate is not authorized to sign other certificates",
	"VESPER-4163" : "issuer name does not match subject from issuing certificate",
	"VESPER-4164" : "other errors - certificate issuer, unauthorized root/intermediate certificate,...",
	"VESPER-4165" : "public key is not a ECDSA public key",
	"VESPER-4166" : "error encountered in verifying signature",
	"VESPER-4167" : "iat value indicates stale date",
	"VESPER-4168" : "unable to validate replay attack",
	"VESPER-4169" : "JWT claims repeated; possible replay attack",
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
