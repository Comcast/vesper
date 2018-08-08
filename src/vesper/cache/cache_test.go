package cache

import (
	"fmt"
	"testing"
	"vesper/cache"
)

func TestAdd(t *testing.T) {
	// Create a new cache
	c := cache.InitObject() // empty
	c.Add(1, "abcd")
	c.Add(1213142, "abcd")
	c.Add(1, "xxgf")
	c.Add(1, "xxgf")
	fmt.Println("Add")
	c.Entries()
}


func TestRemove(t *testing.T) {
	// Create a new cache
	c := cache.InitObject() // empty
	c.Add(1, "abcd")
	c.Add(1213142, "abcd")
	c.Add(1, "xxgf")

	fmt.Println("Remove")
	c.Entries()
			
	fmt.Println("----------")
	
	c.RemoveAll(1)
	c.Entries()
}


func TestValidate(t *testing.T) {
	// Create a new cache
	c := cache.InitObject() // empty
	c.Add(1, "abcd")
	c.Add(1213142, "abcd")
	c.Add(1, "efgh")

	fmt.Println("Validate")
	c.Entries()
			
	fmt.Println("----------")
	fmt.Printf("%v\n", c.IsPresent(1, "efgh"))

	fmt.Println("----------")
	fmt.Printf("%v\n", c.IsPresent(1, "sjdjd"))
}
