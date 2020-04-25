package gorootcheck

import (
	"os"
)

func dirExist(p string) (bool) {
	f, err := os.Stat(p)
	if err != nil {
		return false
	}
	if f.IsDir() {
		return true
	}
	return false
}