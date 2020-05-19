/*
    Rule #3 code - Hidden /dev files and directories
#3    Scan the /dev directory looking for anomalies. 
The /dev should only have device files and the Makedev script. 
A lot of rootkits use the /dev to hide files. 
This technique can detect even non-public rootkits.

In current v0.1 version this module can by easily bypass by
more sophistication malwares
*/

package gorootcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"io/ioutil"
	"crypto/sha1"
)

// printf sha1 of given file
func sha1hash(file string) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Printf(" Error during hashing file process")
	}
	fmt.Printf(" | SHA1 [ %x ]\n", sha1.Sum(content))
}

func devhide(){
	fmt.Println("#3 - Hidden /dev files and directories v0.1")
	err := filepath.Walk("/dev",
    func(path string, info os.FileInfo, err error) error {
    if err != nil {
        return err
	}
	if info.Mode() < 10000 {
		fmt.Printf("\t- Suspicius file - %s", path)
		sha1hash(path)
	}
	
    return nil
	})
	if err != nil {
		fmt.Println("#3 Error")
	}
}