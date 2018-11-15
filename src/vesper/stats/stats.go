package stats

import (
	"sync"
)

var (
	mtx = &sync.RWMutex{}
	minApiProcessingTime int64
	maxApiProcessingTime int64
	totalApiProcessingTime int64
	processingTime0To50ms int64
	processingTime51To100ms int64
	processingTime101To150ms int64
	processingTimeMoreThan151ms int64
	signingRequests int64
	verificationRequests int64
)

// Update min/max API processing time
func UpdateApiProcessingTime(t int64) {
	mtx.Lock()
	defer mtx.Unlock()
	totalApiProcessingTime += t
	switch {
	case t > 0 && t < 51 :
		processingTime0To50ms += 1
	case t > 50 && t < 101 :
		processingTime51To100ms += 1
	case t > 50 && t < 101 :
		processingTime51To100ms += 1
	case t > 100 && t < 151 :
		processingTime101To150ms += 1
	default:
		processingTimeMoreThan151ms += 1
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
		totalRequests := signingRequests+verificationRequests
		resp["avgApiProcessingTime"] = totalApiProcessingTime/totalRequests
		resp["processingTime (0 - 50ms)"] = (float64(processingTime0To50ms)/float64(totalRequests))*100
		resp["processingTime (51 - 100ms)"] = (float64(processingTime51To100ms)/float64(totalRequests))*100
		resp["processingTime (101 - 150ms)"] = (float64(processingTime51To100ms)/float64(totalRequests))*100
		resp["processingTime (more than 150ms)"] = (float64(processingTimeMoreThan151ms)/float64(totalRequests))*100
	}
	return resp
}

// reset stats
func ResetStats() {
	mtx.Lock()
	defer mtx.Unlock()
	minApiProcessingTime = 0
	maxApiProcessingTime = 0
	totalApiProcessingTime = 0
	processingTime0To50ms = 0
	processingTime51To100ms = 0
	processingTime101To150ms = 0
	processingTimeMoreThan151ms = 0
	signingRequests = 0
	verificationRequests = 0
}