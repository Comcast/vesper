package signcredentials

import (
	"fmt"
	"time"
	"sync"
	"strings"
	"io/ioutil"
	"encoding/json"
	"net/http"
	"vesper/configuration"
	"vesper/eks"
	"vesper/sticr"
	"github.com/comcast/irislogger"
)

// globals
var (
	info							*irislogger.Logger
	softwareVersion		string
	httpClient				*http.Client
	eksCredentials		*eks.EksCredentials
	certRepo					*sticr.SticrHost
)


// function to log in specific format
func logInfo(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " vesper=" + configuration.ConfigurationInstance().LogHost + ", Version=" + softwareVersion + ", Code=Info, " + format, args ...)
}

// function to log in specific format
func logError(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " vesper=" + configuration.ConfigurationInstance().LogHost + ", Version=" + softwareVersion + ", Code=ErrorInfo, " + format, args ...)
}

// SigningCredentials - structure that holds all root certs
type SigningCredentials struct {
	sync.RWMutex	// A field declared with a type but no explicit field name is an
					// anonymous field, also called an embedded field or an embedding of
					// the type in the structembedded. see http://golang.org/ref/spec#Struct_types
	x5u					string
	privateKey	string
}
  
// Initialize object
func InitObject(i *irislogger.Logger, v string, h *http.Client, ek *eks.EksCredentials, cr *sticr.SticrHost) (*SigningCredentials, error) {
	info = i
	softwareVersion = v
	httpClient = h
	eksCredentials = ek
	certRepo = cr
	sc := new(SigningCredentials)
	var err error
	sc.x5u, sc.privateKey, err = getSigningCredentialsFromEks()
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// fetch rootcerts from eks
func (sc *SigningCredentials) FetchSigningCredentialsFromEks() error {
	x, p, err := getSigningCredentialsFromEks()
	sc.Lock()
	defer sc.Unlock()
	if err == nil {
		sc.x5u = x
		sc.privateKey = p
	}
	return err
}


// using Lock() ensures all RLocks() are blocked when alerts are being updated
func (sc *SigningCredentials) Signing() (string, string) {
	sc.RLock()
	defer sc.RUnlock()
	return sc.x5u, sc.privateKey
}

func getSigningCredentialsFromEks() (string, string, error) {
	// Request root certs from EKS
	start := time.Now()
	u, t := eksCredentials.GetEksCredentials()
	url := u + "/v1/owner/kms.service.srv/secret/signing/data"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", fmt.Errorf("%v - http.NewRequest failed", err)
	}
	authHdr := "Bearer " + t
	req.Header.Set("Authorization", authHdr)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%v - GET %v failed", err, url)
	}
	defer resp.Body.Close()
	logInfo("Type=eksResponseTime, Module=getSigningCredentialsFromEks, Message=Response time : %v", time.Since(start))
	var s map[string]interface{}
	rb, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		if len(rb) > 0 {
			c := resp.Header.Get("Content-Type")
			if strings.Contains(c, "application/json") {
				err = json.Unmarshal(rb, &s)
				if err != nil {
					return "", "", fmt.Errorf("GET %v response status - %v; unable to parse JSON object in response body (from EKS) - %v", url, resp.StatusCode, err)
				}
			}
		} else {
			return "", "", fmt.Errorf("GET %v response status - %v; nothing read from response body (from EKS)", url, resp.StatusCode)
		}
	} else {
		return "", "", fmt.Errorf("GET %v response status - %v ; %v - response body (from EKS)", url, resp.StatusCode, err)
	}
	switch resp.StatusCode {
	case 200:
		var x, p string
		// s contains
		// x5u
		if r2, ok := s["filename"]; ok {
			switch r2.(type) {
			case string:
				x = certRepo.GetSticrHost() + "/" + s["filename"].(string)
			default:
				return "", "", fmt.Errorf("GET %v response status - %v; \"filename\" field MUST be a string in %+v returned by EKS", url, resp.Status, s)
			}
		} else {
			return "", "", fmt.Errorf("GET %v response status - %v; \"filename\" field missing in in %+v returned by EKS", url, resp.Status, s)
		}
		// privateKey
		if r2, ok := s["privateKey"]; ok {
			switch r2.(type) {
			case string:
				p = s["privateKey"].(string)
			default:
				return "", "", fmt.Errorf("GET %v response status - %v; \"privateKey\" field MUST be a string in %+v returned by EKS", url, resp.Status, s)
			}
		} else {
			return "", "", fmt.Errorf("GET %v response status - %v; \"privateKey\" field missing in in %+v returned by EKS", url, resp.Status, s)	
		}
		return x, p, nil
	}
	return "", "", fmt.Errorf("GET %v response status - %v; response from EKS - %+v", url, resp.StatusCode, s)
}