package eks

import (
	"fmt"
	"sync"
	"os"
	"strings"
	"reflect"
	"encoding/json"
	"github.com/comcast/irisjwt"
)

// globals
var (
	credentialsFileModifiedTime	int64
	credentialsFileName					string
	creds												*EksCredentials
)

// EksCredentials - structure to store core JWT
type EksCredentials struct {
	sync.RWMutex		// A field declared with a type but no explicit field name is an 
						// anonymous field, also called an embedded field or an embedding of
						// the type in the structembedded. see http://golang.org/ref/spec#Struct_types
	aumUrl						string
	aumKey						string
	aumSecret					string
	eksUrl						string
	eksJwtExpiryTime	int64
	eksJwt						string
}

// using Lock() ensures all RLocks() are blocked when credentials is being updated
func (k *EksCredentials) setEksCredentials(aumUrl, aumKey, aumSecret, eksUrl, j string, t int64) {
	k.Lock()
	defer k.Unlock()
	k.aumUrl = aumUrl
	k.aumKey = aumKey
	k.aumSecret = aumSecret
	k.eksUrl = eksUrl
	k.eksJwtExpiryTime = t
	k.eksJwt = j
}

// using Lock() ensures all RLocks() are blocked when credentials is being updated
func (k *EksCredentials) updateEksJwt(j string, t int64) {
	k.Lock()
	defer k.Unlock()
	k.eksJwtExpiryTime = t
	k.eksJwt = j
}

// using Rlock() allows multiple goroutines to read at the "same" time
func (k *EksCredentials) GetEksCredentials() (string, string) {
	k.RLock()
	defer k.RUnlock()
	return k.eksUrl, k.eksJwt
}

// Initialize object
// Saves file modified time for future use
func InitObject(f string) (*EksCredentials, error) {
	if len(strings.TrimSpace(f)) == 0 {
		return nil, fmt.Errorf("eks file name is an empty string")
	}
	credentialsFileName = f
	aumUrl, key, secret, eksUrl, err := readEksCredentialsFile(credentialsFileName)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	_, jwt, err := irisjwt.GetServerJwt(aumUrl, key, secret)
	if err != nil {
		return nil, fmt.Errorf("%v - aumUrl: %v, aumKey: %v, aumSecret: %v", err, aumUrl, key, secret)
	}
	tm, err := irisjwt.JwtExpiryTime(jwt)
	if err != nil {
		return nil, fmt.Errorf("%v- %v", err, jwt)
	}
	creds = &EksCredentials{aumUrl: aumUrl, aumKey: key, aumSecret: secret, eksUrl: eksUrl, eksJwtExpiryTime: tm, eksJwt: jwt}
	return creds, nil
}

// refresh server JWT
func (k *EksCredentials) RefreshEksCredentials() error {
	k.RLock()
		aumUrl := k.aumUrl
		key := k.aumKey
		secret := k.aumSecret
	k.RUnlock()
	_, jwt, err := irisjwt.GetServerJwt(aumUrl, key, secret)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	tm, err := irisjwt.JwtExpiryTime(jwt)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	k.updateEksJwt(jwt, tm)
	return nil
}

// update eks cfredentials
func (k *EksCredentials) UpdateEksCredentials() error {
	aumUrl, key, secret, eksUrl, err := readEksCredentialsFile(credentialsFileName)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(strings.TrimSpace(aumUrl)) == 0 && len(strings.TrimSpace(key)) == 0 && len(strings.TrimSpace(secret)) == 0 && len(strings.TrimSpace(eksUrl)) == 0 {
		// no changes in config file
		// refresh server JWT anyway with existing key/secret
		return k.RefreshEksCredentials()
	}
	_, jwt, err := irisjwt.GetServerJwt(aumUrl, key, secret)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	tm, err := irisjwt.JwtExpiryTime(jwt)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	k.setEksCredentials(aumUrl, key, secret, eksUrl, jwt, tm)
	return nil
}

// Read eks credentials file only if file modified time has changed
func readEksCredentialsFile(n string) (string, string, string, string, error) {
	f, err := os.Open(n)
	if err != nil {
		return "", "", "", "", fmt.Errorf("%v - eks credentials file", err)
	}
	defer f.Close()
	
	if fi, err := f.Stat(); err == nil {
		m := fi.ModTime().Unix()
		if credentialsFileModifiedTime == m {
			return "", "", "", "", nil
		}
		// save the latest modified time
		credentialsFileModifiedTime = m
	}
	// We are here because the timestamp for eks credentials  file has changed
	// This may mean that updates to credentials is available
	var c map[string]interface{}
	decoder := json.NewDecoder(f)
	err = decoder.Decode(&c)
	if err != nil {
		return "", "", "", "", fmt.Errorf("%v - decode JSON object in eks credentials file", err)
	}
	var u, k, s, e string
	// validate required fields
	if reflect.ValueOf(c["aum"]).IsValid() {
		switch reflect.TypeOf(c["aum"]).Kind() {
		case reflect.Map:
			keys := reflect.ValueOf(c["aum"]).MapKeys()
			switch {
			case len(keys) != 3 :
				return "", "", "", "", fmt.Errorf("\"aum\" field MUST be a JSON object with 3 fields")
			default:
				var ok bool
				if _, ok = c["aum"].(map[string]interface{})["url"]; !ok {
					return "", "", "", "", fmt.Errorf("\"url\" field MUST be present")
				}
				if u, ok = c["aum"].(map[string]interface{})["url"].(string); !ok {
					return "", "", "", "", fmt.Errorf("\"url\" field MUST be a string")
				}
				if _, ok = c["aum"].(map[string]interface{})["key"]; !ok {
					return "", "", "", "", fmt.Errorf("\"key\" field MUST be present")
				}
				if k, ok = c["aum"].(map[string]interface{})["key"].(string); !ok {
					return "", "", "", "", fmt.Errorf("\"key\" field MUST be a string")
				}
				if _, ok = c["aum"].(map[string]interface{})["secret"]; !ok {
					return "", "", "", "", fmt.Errorf("\"secret\" field MUST be present")
				}
				if s, ok = c["aum"].(map[string]interface{})["secret"].(string); !ok {
					return "", "", "", "", fmt.Errorf("\"secret\" field MUST be a string")
				}
			}
		default:
			return "", "", "", "", fmt.Errorf("\"aum\" field MUST be a JSON object")
		}			
	} else {
		return "", "", "", "", fmt.Errorf("\"eks\" field missing in credentials config file")
	}
	if reflect.ValueOf(c["eks"]).IsValid() {
		switch reflect.TypeOf(c["eks"]).Kind() {
		case reflect.String:
			e = reflect.ValueOf(c["eks"]).String()
		default:
			return "", "", "", "", fmt.Errorf("\"eks\" field MUST be a string")
		}			
	} else {
		return "", "", "", "", fmt.Errorf("\"eks\" field missing in credentials config file")
	}
	if len(strings.TrimSpace(u)) == 0 || len(strings.TrimSpace(k)) == 0 || len(strings.TrimSpace(s)) == 0 || len(strings.TrimSpace(e)) == 0 {
		return "", "", "", "", fmt.Errorf("Invalid value(s) detected in config file")
	}
	return u, k, s, e, nil
}
