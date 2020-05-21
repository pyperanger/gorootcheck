package gorootcheck

import (
	"fmt"
	"os"
	"path/filepath"
)


/**func sha1hash(file string) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Printf(" Error during hashing file process")
	}
	fmt.Printf(" | SHA1 [ %x ]\n", sha1.Sum(content))
}
**/
func permproblems() {

	fmt.Println("#4 Scan the whole filesystem looking for unusual files and permission problems. v 0.1")
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
	if info.Mode() == 4000 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	if info.Mode() == 0700 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	if info.Mode() == 0440 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	if info.Mode() == 0111 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	if info.Mode() == 0777 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	if info.Mode() == 0400 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	if info.Mode() == 0440 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	if info.Mode() == 0444 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	if info.Mode() == 0100 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	if info.Mode() == 0110 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}	


    return nil
	})
	if err != nil {
		fmt.Println("#4 Error")
	}
}
