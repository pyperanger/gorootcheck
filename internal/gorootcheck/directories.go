package gorootcheck

import (
	"fmt"
	"os"
)

// verify if dir exist
func dirExist(p string) bool {
	f, err := os.Stat(p)
	if err != nil {
		fmt.Println(p, ": Not found")
		return false
	}
	if f.IsDir() {
		return true
	}
	return false
}
