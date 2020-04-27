package gorootcheck

import (
	"fmt"
	"regexp"
)

var (
	rootfiles = [2]string{"rootkit_files.txt", "rootkit_trojans.txt"}
)

// Check if workdir exist
// and if at least rootkit_files,
// rootkit_trojans.txt is in there
// for basic scan in rule #1 and #2
func dbCheck() bool {
	if !dirExist(*workdir) {
		fmt.Println(*workdir, ": Not found")
		return false
	}
	for _, f := range rootfiles {
		if !fileExist(*workdir, f) {
			fmt.Println(f, ": Minimal file not found")
			return false
		}
	}
	return true
}

// Create the map with regex combinations
// Key=>FilePath , Value=>MaliciusName
func dbRkregex(line []string) map[string]string {
	dbgex := make(map[string]string)
	path, _ := regexp.Compile(`(?m)^(\S+).+[!,|].(\S+.\S+)`)

	for _, l := range line {
		dbgex[path.FindStringSubmatch(l)[1]] = path.FindStringSubmatch(l)[2]
	}
	return dbgex
}

// Make a map based on basic structure of
// rootkit_files.txt file.
// # file_name ! Name ::Link to it
func dbRkfile() map[string]string {
	rkfile, err := fileReadline(*workdir + "/rootkit_files.txt")
	if err != nil {
		fmt.Println("Where go rootkit_files.txt? u try race condition me?!")
		bye()
	}
	return dbRkregex(fileRkfilter(rkfile))
}
