/*
	file.go
	Important code for rules #1 and #2.
	Checks rootkit_trojans and assignatures in filesystem
	Use some syscall to figure out if system as been infected
*/
package gorootcheck

import (
	"bufio"
	"os"
)

// p path f file
func fileExist(p string, f string) bool {
	if _, err := os.Stat(p + "/" + f); os.IsNotExist(err) || os.IsPermission(err) {
		return false
	}
	return true
}

// read line by line into slice
func fileReadline(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// clean mess in rootkit_file.txt
func fileRkfilter(line []string) []string {
	var cleanfile []string
	for _, l := range line {
		if len(l) > 0 && l[0] != '#' {
			cleanfile = append(cleanfile, l)
		}
	}
	return cleanfile
}
