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
	"vesper/sks"
	"vesper/sticr"
	"github.com/comcast/irislogger"
)

// globals
var (
	info							*irislogger.Logger
	softwareVersion		string
	httpClient				*http.Client
	sksCredentials		*sks.SksCredentials
	certRepo					*sticr.SticrHost
)


// function to log in specific format
func logInfo(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " vesper=" + configuration.ConfigurationInstance().Host + ", Version=" + softwareVersion + ", Code=Info, " + format, args ...)
}

// function to log in specific format
func logError(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " vesper=" + configuration.ConfigurationInstance().Host + ", Version=" + softwareVersion + ", Code=ErrorInfo, " + format, args ...)
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
func InitObject(i *irislogger.Logger, v string, h *http.Client, sk *sks.SksCredentials, cr *sticr.SticrHost) (*SigningCredentials, error) {
	info = i
	softwareVersion = v
	httpClient = h
	sksCredentials = sk
	certRepo = cr
	sc := new(SigningCredentials)
	var err error
	sc.x5u, sc.privateKey, err = getSigningCredentialsFromSks()
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// fetch rootcerts from sks
func (sc *SigningCredentials) FetchSigningCredentialsFromSks() error {
	x, p, err := getSigningCredentialsFromSks()
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

func getSigningCredentialsFromSks() (string, string, error) {
	// Request root certs from SKS
	start := time.Now()
	u, t := sksCredentials.GetSksCredentials()
	url := u + "/current/signing"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", fmt.Errorf("%v - http.NewRequest failed", err)
	}
	req.Header.Set("X-Vault-Token", t)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%v - GET %v failed", err, url)
	}
	defer resp.Body.Close()
	logInfo("Type=vesperRequestResponseTime, Module=getSigningCredentialsFromSks, Message=Response time : %v", time.Since(start))
	var s map[string]interface{}
	rb, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		if len(rb) > 0 {
			c := resp.Header.Get("Content-Type")
			if strings.Contains(c, "application/json") {
				err = json.Unmarshal(rb, &s)
				if err != nil {
					return "", "", fmt.Errorf("GET %v response status - %v; unable to parse JSON object in response body (from SKS) - %v", url, resp.StatusCode, err)
				}
			}
		} else {
			return "", "", fmt.Errorf("GET %v response status - %v; nothing read from response body (from SKS)", url, resp.StatusCode)
		}
	} else {
		return "", "", fmt.Errorf("GET %v response status - %v ; %v - response body (from SKS)", url, resp.StatusCode, err)
	}
	switch resp.StatusCode {
	case 200:
		var x, p string
		// s contains
		if data, ok := s["data"]; ok {
			switch r1 := data.(type) {
			case map[string]interface{}:
				// x5u
				if r2, ok := r1["filename"]; ok {
					switch r2.(type) {
					case string:
						x = certRepo.GetSticrHost() + "/" + r1["filename"].(string)
					default:
						return "", "", fmt.Errorf("GET %v response status - %v; \"filename\" field MUST be a string in %+v returned by SKS", url, resp.Status, s)
					}
				} else {
					return "", "", fmt.Errorf("GET %v response status - %v; \"filename\" field missing in in %+v returned by SKS", url, resp.Status, s)	
				}
				// privateKey
				if r2, ok := r1["privateKey"]; ok {
					switch r2.(type) {
					case string:
						p = r1["privateKey"].(string)
					default:
						return "", "", fmt.Errorf("GET %v response status - %v; \"privateKey\" field MUST be a string in %+v returned by SKS", url, resp.Status, s)
					}
				} else {
					return "", "", fmt.Errorf("GET %v response status - %v; \"privateKey\" field missing in in %+v returned by SKS", url, resp.Status, s)	
				}
				return x, p, nil
			default:
				return "", "", fmt.Errorf("GET %v response status - %v; \"data\" field MUST be a map in %+v returned by SKS", url, resp.Status, s)
			}
		}
		return "", "", fmt.Errorf("GET %v response status - %v; \"data\" field missing in in %+v returned by SKS", url, resp.Status, s)
	}
	return "", "", fmt.Errorf("GET %v response status - %v; response from SKS - %+v", url, resp.StatusCode, s)
}