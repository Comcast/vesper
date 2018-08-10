// Package cache implements a multimap similar to STL in C++
//
// This data structure does hold duplicate key-value pairs
//
// This data structure is thread safe.
package replayattack

import (
	"fmt"
	"sync"
)

var exists = struct{}{}

// set represents a set object
type Set map[interface{}]struct{}

// IdentityCache holds the elements in go's native map.
type Cache struct {
	sync.RWMutex	// A field declared with a type but no explicit field name is an
					// anonymous field, also called an embedded field or an embedding of
					// the type in the structembedded. see http://golang.org/ref/spec#Struct_types
	cache map[interface{}]Set
}

// Initialize object
func InitObject() (*Cache) {
	return &Cache{cache: make(map[interface{}]Set)}
}

// Add2Cache caches a key-value pair
func (c *Cache) Add(key interface{}, value interface{}) {
	c.Lock()
	defer c.Unlock()
	s, f := c.cache[key]
	if f {
		if _, ok := s[value]; ok {
			return
		}
		s[value] = exists
		c.cache[key] = s
	} else {
		s = make(Set)
		s[value] = exists
		c.cache[key] = s
	}
}

// IsPresent returns true if cache contains key-value pair
func (c *Cache) IsPresent(key interface{}, value interface{}) bool {
	c.RLock()
	defer c.RUnlock()
	s, f := c.cache[key]
	if f {
		if _, ok := s[value]; ok {
			return true
		}
	}
	return false
}

// deletes all values cached for a key. 
func (c *Cache) Remove(key interface{}) {
	c.Lock()
	defer c.Unlock()
	delete(c.cache, key)
}

// Clear removes all elements from the map.
func (c *Cache) Clear() {
	c.Lock()
	defer c.Unlock()
	c.cache = make(map[interface{}]Set)
}

// get all entries in cache
func (c *Cache) Entries() {
	c.RLock()
	defer c.RUnlock()
	for key, set := range c.cache {
		for value := range set {
			fmt.Printf("key: %v, Value: %v\n", key, value)
		}
	}
}
