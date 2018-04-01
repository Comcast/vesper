package sks

import (
	"fmt"
	"sync"
	"os"
	"strings"
	"reflect"
	"encoding/json"
)

// globals
var (
	sksCredentialsFileModifiedTime	int64
	sksCredentialsFileName					string
)


// SksCredentials - structure to store core JWT
type SksCredentials struct {
	sync.RWMutex		// A field declared with a type but no explicit field name is an 
						// anonymous field, also called an embedded field or an embedding of
						// the type in the structembedded. see http://golang.org/ref/spec#Struct_types
	sksUrl string
	sksToken  string
}

// using Lock() ensures all RLocks() are blocked when credentials is being updated
func (k *SksCredentials) setSksCredentials(u, t string) {
  k.Lock()
  defer k.Unlock()
  k.sksUrl = u
  k.sksToken = t
}

// using Rlock() allows multiple goroutines to read at the "same" time
func (k *SksCredentials) GetSksCredentials() (string, string) {
  k.RLock()
  defer k.RUnlock()
  return k.sksUrl, k.sksToken
}

// Initialize object
// Saves file modified time for future use
func InitObject(f string) (*SksCredentials, error) {
	if len(strings.TrimSpace(f)) == 0 {
		return nil, fmt.Errorf("sks file name is an empty string")
	}
	sksCredentialsFileName = f
	u, t, err := readSksCredentialsFile(sksCredentialsFileName)
	if err == nil {	
		if len(strings.TrimSpace(u)) > 0 && len(strings.TrimSpace(t)) > 0 {
			return &SksCredentials{sksUrl: u, sksToken: t}, nil
		}
		return nil, fmt.Errorf("\"sks\"/\"token\" value(s) is an empty string")
	}
	return nil, err
}

// update sks cfredentials
func (k *SksCredentials) UpdateSksCredentials() error {
	u, t, err := readSksCredentialsFile(sksCredentialsFileName)
	if err == nil {	
		if len(strings.TrimSpace(u)) > 0 && len(strings.TrimSpace(t)) > 0 {
			k.setSksCredentials(u, t)
		}
		return fmt.Errorf("\"sks\"/\"token\" value(s) is an empty string")
	}
	return err
}

// Read sks credentials file only if file modified time has changed
func readSksCredentialsFile(n string) (string, string, error) {
	f, err := os.Open(n)
	if err != nil {
		return "", "", fmt.Errorf("%v - sks credentials file", err)
	}
	defer f.Close()
	
	if fi, err := f.Stat(); err == nil {
		m := fi.ModTime().Unix()
		if sksCredentialsFileModifiedTime == m {
			return "", "", fmt.Errorf("sks credentials file has not been modified since last lookup")
		}
		// save the latest modified time
		sksCredentialsFileModifiedTime = m
	}
	// We are here because the timestamp for sks credentials  file has changed
	// This may mean that updates to credentials is available
	var c map[string]string
	decoder := json.NewDecoder(f)
	err = decoder.Decode(&c)
	if err != nil {
		return "", "", fmt.Errorf("%v - decode JSON object in sks credentials file", err)
	}
	var u, t string
	// validate required fields
	if reflect.ValueOf(c["sks"]).IsValid() {
		switch reflect.TypeOf(c["sks"]).Kind() {
		case reflect.String:
			u = reflect.ValueOf(c["sks"]).String()
		default:
			return "", "", fmt.Errorf("\"sks\" field MUST be a string")
		}			
	} else {
		return "", "", fmt.Errorf("\"sks\" field missing in credentials config file")
	}
	if reflect.ValueOf(c["token"]).IsValid() {
		switch reflect.TypeOf(c["token"]).Kind() {
		case reflect.String:
			t = reflect.ValueOf(c["token"]).String()
		default:
			return "", "", fmt.Errorf("\"token\" field MUST be a string")
		}			
	} else {
		return "", "", fmt.Errorf("\"token\" field missing in credentials config file")
	}
	return u, t, nil
}
