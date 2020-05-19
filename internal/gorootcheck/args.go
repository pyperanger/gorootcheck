package gorootcheck

import (
	"flag"
	"os"
	"fmt"
)

var (
	workdir = flag.String("w", "./", "Path with database datails and signatures")
	version = flag.Bool("version", false, "Show version")
	help    = flag.Bool("h", false, "This massage")
	VERSION = "0.7.0"
)

func argsUsage() {
	fmt.Println(`GoRootCheck - OSSEC Standalone RootCheck in GO
v` + VERSION + ` - github.com/pyperanger/gorootcheck
`)
}

func Args() bool {
	argsUsage()
	if os.Getuid() != 0 {
		fmt.Println("- Run gorootcheck as root")
		bye()
	}
	flag.Parse()
	if *help {
		flag.Usage()
		bye()
	}
	if !dbCheck() {
		return false
	}
	return true
}
