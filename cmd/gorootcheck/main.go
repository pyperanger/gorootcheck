package main

import (
	"github.com/pyperanger/gorootcheck/internal/gorootcheck"
)

// Call the package gorootcheck Main
func main(){
	if gorootcheck.Args() {
		gorootcheck.Main();	
	}
}