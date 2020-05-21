package gorootcheck

import (
	"fmt"
	"os"
	"io/ioutil"
	"crypto/sha1"
)

func bye() {
	os.Exit(0)
}

func banner() {
	fmt.Println(`
 ██████   ██████  ██████   ██████   ██████  ████████  ██████ ██   ██ ███████  ██████ ██   ██ 
██       ██    ██ ██   ██ ██    ██ ██    ██    ██    ██      ██   ██ ██      ██      ██  ██  
██   ███ ██    ██ ██████  ██    ██ ██    ██    ██    ██      ███████ █████   ██      █████   
██    ██ ██    ██ ██   ██ ██    ██ ██    ██    ██    ██      ██   ██ ██      ██      ██  ██  
 ██████   ██████  ██   ██  ██████   ██████     ██     ██████ ██   ██ ███████  ██████ ██   ██ 
	                                                                                                                                                                                                    
	`)
}


// printf sha1 of given file
func sha1hash(file string) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Printf(" Error during hashing file process")
	}
	fmt.Printf(" | SHA1 [ %x ]\n", sha1.Sum(content))
}