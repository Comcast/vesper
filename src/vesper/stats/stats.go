package stats

import (
	"sync"
)

var (
	mtx = &sync.RWMutex{}
	minApiProcessingTime int64
	maxApiProcessingTime int64
	processingTime0To25ms int64
	processingTime26To50ms int64
	processingTime51To100ms int64
	processingTime101To150ms int64
	processingTime151To300ms int64
	processingTime301To600ms int64
	processingTime601To1000ms int64
	processingTimeMoreThan1000ms int64
	signingRequests int64
	verificationRequests int64
)

type processingTime struct {
	Count int64 `json:"count"`
	Percentage float64 `json:"percentage"`
}

// Update min/max API processing time
func UpdateApiProcessingTime(t int64) {
	mtx.Lock()
	defer mtx.Unlock()
	switch {
	case t >= 0 && t < 26 :
		processingTime0To25ms += 1
	case t > 25 && t < 51 :
		processingTime26To50ms += 1
	case t > 50 && t < 101 :
		processingTime51To100ms += 1
	case t > 100 && t < 151 :
		processingTime101To150ms += 1
	case t > 150 && t < 300 :
		processingTime151To300ms += 1
	case t > 300 && t < 601 :
		processingTime301To600ms += 1
	case t > 600 && t < 1001 :
		processingTime601To1000ms += 1
	default:
		processingTimeMoreThan1000ms += 1
	}
	switch {
	case minApiProcessingTime == 0 && maxApiProcessingTime == 0 :
		minApiProcessingTime = t
		maxApiProcessingTime = t
	case t < minApiProcessingTime :
		minApiProcessingTime = t
	case t > maxApiProcessingTime :
		maxApiProcessingTime = t
	}
}

// increment number of signing requests
func IncrSigningRequestCount() {
	mtx.Lock()
	defer mtx.Unlock()
	signingRequests += 1
}

// increment number of verification requests
func IncrVerificationRequestCount() {
	mtx.Lock()
	defer mtx.Unlock()
	verificationRequests += 1
}

// retrieve stats
func Stats() map[string]interface{} {
	mtx.RLock()
	defer mtx.RUnlock()
	
	resp := make(map[string]interface{})
	resp["signingRequests"] = signingRequests
	resp["verificationRequests"] = verificationRequests
	if signingRequests > 0 || verificationRequests > 0 {
		resp["minApiProcessingTime"] = minApiProcessingTime
		resp["maxApiProcessingTime"] = maxApiProcessingTime
		total := processingTime0To25ms+processingTime26To50ms+processingTime51To100ms+processingTime101To150ms+processingTime151To300ms+processingTime301To600ms+processingTime601To1000ms+processingTimeMoreThan1000ms
		resp["processingTime (0 - 25ms)"] = &processingTime{processingTime0To25ms, (float64(processingTime0To25ms)/float64(total))*100}
		resp["processingTime (26 - 50ms)"] = &processingTime{processingTime26To50ms, (float64(processingTime26To50ms)/float64(total))*100}
		resp["processingTime (51 - 100ms)"] = &processingTime{processingTime51To100ms, (float64(processingTime51To100ms)/float64(total))*100}
		resp["processingTime (101 - 150ms)"] = &processingTime{processingTime51To100ms, (float64(processingTime51To100ms)/float64(total))*100}
		resp["processingTime (151 - 300ms)"] = &processingTime{processingTime151To300ms, (float64(processingTime151To300ms)/float64(total))*100}
		resp["processingTime (301 - 600ms)"] = &processingTime{processingTime301To600ms, (float64(processingTime301To600ms)/float64(total))*100}
		resp["processingTime (601 - 1000ms)"] = &processingTime{processingTime601To1000ms, (float64(processingTime601To1000ms)/float64(total))*100}
		resp["processingTime (more than 1000ms)"] = &processingTime{processingTimeMoreThan1000ms, (float64(processingTimeMoreThan1000ms)/float64(total))*100}
	}
	return resp
}

// reset stats
func ResetStats() {
	mtx.Lock()
	defer mtx.Unlock()
	minApiProcessingTime = 0
	maxApiProcessingTime = 0
	processingTime0To25ms = 0
	processingTime26To50ms = 0
	processingTime51To100ms = 0
	processingTime101To150ms = 0
	processingTime151To300ms = 0
	processingTime301To600ms = 0
	processingTime601To1000ms = 0
	processingTimeMoreThan1000ms = 0
	signingRequests = 0
	verificationRequests = 0
}