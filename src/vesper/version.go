// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"net/http"
	"encoding/json"
	"github.com/httprouter"
)

const softwareVersion = `Vesper 1.0`

// VersionQueryResponse -- struct that holds software version
type VersionQueryResponse struct {
	Version string
}

func version(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {

	var jsonResp VersionQueryResponse
	jsonResp.Version = softwareVersion
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	json.NewEncoder(response).Encode(jsonResp)
}
