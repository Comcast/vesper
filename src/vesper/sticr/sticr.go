package sticr

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
	sticrFileModifiedTime	int64
	sticrFileName					string
)


// SticrHost ....
type SticrHost struct {
	sync.RWMutex		// A field declared with a type but no explicit field name is an 
						// anonymous field, also called an embedded field or an embedding of
						// the type in the structembedded. see http://golang.org/ref/spec#Struct_types
	sticrHost string
}

// using Lock() ensures all RLocks() are blocked when credentials is being updated
func (x *SticrHost) setSticrHost(h string) {
  x.Lock()
  defer x.Unlock()
  x.sticrHost = h
}

// using Rlock() allows multiple goroutines to read at the "same" time
func (x *SticrHost) GetSticrHost() string {
  x.RLock()
  defer x.RUnlock()
  return x.sticrHost
}

// Initialize object
// Saves file modified time for future use
func InitObject(f string) (*SticrHost, error) {
	if len(strings.TrimSpace(f)) == 0 {
		return nil, fmt.Errorf("=file name (with stir host) is an empty string")
	}
	sticrFileName = f
	h, err := readSticrHostFile(sticrFileName)
	if err == nil {	
		if len(strings.TrimSpace(h)) > 0 {
			return &SticrHost{sticrHost: h}, nil
		}
		return nil, fmt.Errorf("\"sticrHost\" value(s) is an empty string")
	}
	return nil, err
}

// update sticr host value
func (x *SticrHost) UpdateSticrHost() error {
	h, err := readSticrHostFile(sticrFileName)
	if err == nil {	
		if len(strings.TrimSpace(h)) > 0 {
			x.setSticrHost(h)
		}
		return fmt.Errorf("\"sticrHost\" value(s) is an empty string")
	}
	return err
}

// Read sticr host file only if file modified time has changed
func readSticrHostFile(n string) (string, error) {
	f, err := os.Open(n)
	if err != nil {
		return "", fmt.Errorf("%v - x5u file", err)
	}
	defer f.Close()
	
	if fi, err := f.Stat(); err == nil {
		m := fi.ModTime().Unix()
		if sticrFileModifiedTime == m {
			return "", fmt.Errorf("sticr host file has not been modified since last lookup")
		}
		// save the latest modified time
		sticrFileModifiedTime = m
	}
	// We are here because the timestamp for sticr host file has changed
	// This may mean that updates to x5u host is available
	var c map[string]string
	decoder := json.NewDecoder(f)
	err = decoder.Decode(&c)
	if err != nil {
		return "", fmt.Errorf("%v - decode JSON object in sticr host file", err)
	}
	var h string
	// validate required fields
	if reflect.ValueOf(c["sticrHost"]).IsValid() {
		switch reflect.TypeOf(c["sticrHost"]).Kind() {
		case reflect.String:
			h = reflect.ValueOf(c["sticrHost"]).String()
		default:
			return "", fmt.Errorf("\"sticrHost\" field MUST be a string")
		}			
	} else {
		return "", fmt.Errorf("\"sticrHost\" field missing in sticr host file")
	}
	return h, nil
}
