/*
	Rule #4
#4    Scan the whole filesystem looking for unusual 
files and permission problems. Files owned by root, 
with write permission to others are very dangerous, 
and the rootkit detection will look for them. Suid 
files, hidden directories and files will also be 
inspected.


This rule was coded by bloodr00t
Thank you. 
*/

package gorootcheck

import (
	"fmt"
	"os"
	"path/filepath"
)

func permproblems() {
	fmt.Println("#4 Scan the whole filesystem looking for unusual files and permission problems. v 0.1")
	
	perms := [9]int{4000, 0700, 0440, 0111, 0400, 0440, 0444, 0100, 0110}
	
	err := filepath.Walk("/",
    	func(path string, info os.FileInfo, err error) error {
    	if err != nil {
        	return err
		}
	if info.IsDir() && info.Name() == "dev" {
		return filepath.SkipDir
	}
	if info.IsDir() && info.Name() == "proc" {
		return filepath.SkipDir
	}
	if info.IsDir() && info.Name() == "run" {
		return filepath.SkipDir
	}
	if info.IsDir() && info.Name() == "sys" {
		return filepath.SkipDir
	}

	for _, perm := range perms {
		if int(info.Mode()) == perm {
			fmt.Printf("\t- Suspicius file - %s", path)
			sha1hash(path)		
		}
	}
	return nil
	})
	if err != nil {
		fmt.Println("#4 Error")
	}
}