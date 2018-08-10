package publickeys

import (
	"fmt"
	"sync"
)

var (
	mtx = &sync.RWMutex{}
	publicKeys = map[string]string{}
)

// returns cached public key if present
func Fetch(x5u string) string {
	// check if public key is cached
	var pk string
	mtx.RLock()
	defer mtx.RUnlock()
	if _, ok := publicKeys[x5u]; ok {
		pk = publicKeys[x5u]
	}
	return pk
}

// caches public key
func Add(x5u, pk string) {
	mtx.Lock()
	defer mtx.Unlock()
	publicKeys[x5u] = pk
}

// clears all cached public keys
func FlushCache() {
	mtx.Lock()
	defer mtx.Unlock()
	for k, _ := range publicKeys {
		delete(publicKeys, k)
	}
}

// prints all entries in cache
func Entries() {
	mtx.RLock()
	defer mtx.RUnlock()
	for x5u, pk := range publicKeys {
		fmt.Printf("x5u: %v, pk: %v\n", x5u, pk)
	}
}
