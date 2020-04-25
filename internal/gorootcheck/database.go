package gorootcheck


// Check if workdir exist 
// and if at least rootkit_files,
// rootkit_trojans.txt is in there
// for basic scan in rule #1 and #2
func dbCheck(p string) bool {
	if !dirExist(*p) {
		fmt.Println(*p, ": Not found")
		return false
	}


}
