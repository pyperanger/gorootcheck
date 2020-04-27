/*
	Rule #1 code

	#1 Read the rootkit_files.txt which contains a database of rootkits and files
	commonly used by them. It will try to stats, fopen and opendir each specified
	file. We use all these system calls because some kernel-level rootkits hide
	files from some system calls. The more system calls we try, the better the detection.
	This method is more like an anti-virus rule that needs to be updated constantly.
	The chances of false-positives are small, but false negatives can be produced by modifying the rootkits.

*/
package gorootcheck

import (
	"fmt"
)

func rkExist(f string) bool {
	// NATIVE GOLANG
	if fileExist("/", f) {
		return true
	}
	// Syscall Stat
	if fileStats("/", f) {
		return true
	}

	return false
}

func rootkit_files() bool {
	fmt.Println("#1 - Searching for malicius files -> rootkit_files.txt")
	maprk := dbRkfile()

	for f, n := range maprk {
		if rkExist(f) {
			fmt.Println(" - Malicius file: ", n, " in ", f)
		}
	}

	return true
}
