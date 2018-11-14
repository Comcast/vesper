package publickeys

import (
	"fmt"
	"sync"
	"crypto/ecdsa"
)

var (
	mtx = &sync.RWMutex{}
	publicKeys = make(map[string]*ecdsa.PublicKey)
)

// returns cached public key if present
func Fetch(x5u string) *ecdsa.PublicKey {
	// check if public key is cached
	mtx.RLock()
	defer mtx.RUnlock()
	if _, ok := publicKeys[x5u]; ok {
		return publicKeys[x5u]
	}
	return nil
}

// caches public key
func Add(x5u string, pk *ecdsa.PublicKey) {
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
