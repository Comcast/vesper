package rootcerts

import (
	"fmt"
	"time"
	"sync"
	"strings"
	"io/ioutil"
	"encoding/json"
	"crypto/x509"
	"net/http"
	"vesper/eks"
	kitlog "github.com/go-kit/kit/log"
)

// globals
var (
	softwareVersion			string
	httpClient					*http.Client
	eksCredentials			*eks.EksCredentials
)

// RootCerts - structure that holds all root certs
type RootCerts struct {
	sync.RWMutex	// A field declared with a type but no explicit field name is an
					// anonymous field, also called an embedded field or an embedding of
					// the type in the structembedded. see http://golang.org/ref/spec#Struct_types
	certs *x509.CertPool
}
  
// Initialize object
func InitObject(l kitlog.Logger, v string, h *http.Client, s *eks.EksCredentials) (*RootCerts, error) {
	glogger = l
	softwareVersion = v
	httpClient = h
	eksCredentials = s
	rc := new(RootCerts)
	var err error
	rc.certs, err = getRootCertsFromEks()
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// fetch rootcerts from eks
func (rc *RootCerts) FetchRootCertsFromEks() error {
	c, err := getRootCertsFromEks()
	rc.Lock()
	defer rc.Unlock()
	if err == nil {
		rc.certs = c
	}
	return err
}


// using Lock() ensures all RLocks() are blocked when alerts are being updated
func (rc *RootCerts) Root() *x509.CertPool {
	rc.RLock()
	defer rc.RUnlock()
	return rc.certs
}

func getRootCertsFromEks() (*x509.CertPool, error) {
	certs := x509.NewCertPool()
	// Request root certs from EKS
	start := time.Now()
	u, t := eksCredentials.GetEksCredentials()
	url := u + "/v1/owner/kms.service.srv/secret/whitelist/data"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%v - http.NewRequest failed", err)
	}
	authHdr := "Bearer " + t
	req.Header.Set("Authorization", authHdr)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%v - GET %v failed", err, url)
	}
	defer resp.Body.Close()
	logInfo("type", "eksResponseTime", "module", "getRootCertsFromEks", "eksResponseTime", fmt.Sprintf("%v", time.Since(start)))
	var s map[string]interface{}
	rb, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		if len(rb) > 0 {
			c := resp.Header.Get("Content-Type")
			if strings.Contains(c, "application/json") {
				err = json.Unmarshal(rb, &s)
				if err != nil {
					return nil, fmt.Errorf("GET %v response status - %v; unable to parse JSON object in response body (from EKS) - %v", url, resp.StatusCode, err)
				}
			}
		} else {
			return nil, fmt.Errorf("GET %v response status - %v; nothing read from response body (from EKS)", url, resp.StatusCode)
		}
	} else {
		return nil, fmt.Errorf("GET %v response status - %v; %v - response body (from EKS)", url, resp.StatusCode, err)
	}
	switch resp.StatusCode {
	case 200:
		// s contains
		if r2, ok := s["rootcerts"]; ok {
			switch r2.(type) {
			case string:
				// Append our cert to the system pool
				if ok := certs.AppendCertsFromPEM([]byte(s["rootcerts"].(string))); !ok {
					return nil, fmt.Errorf("No certs appended")
				}
				return certs, nil
			default:
				return nil, fmt.Errorf("GET %v response status - %v; \"rootcerts\" field MUST be a string in %+v returned by EKS", url, resp.Status, s)
			}
		} else {
			return nil, fmt.Errorf("GET %v response status - %v; \"rootcerts\" field missing in in %+v returned by EKS", url, resp.Status, s)	
		}
	}
	return nil, fmt.Errorf("GET %v response status - %v; response from EKS - %+v", url, resp.StatusCode, s)
}
