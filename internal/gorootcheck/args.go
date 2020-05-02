package gorootcheck

import (
	"flag"
	"fmt"
)

var (
	workdir = flag.String("w", "./", "Path with database datails and signatures")
	version = flag.Bool("version", false, "Show version")
	debug   = flag.Bool("v", false, "Debug mode")
	help    = flag.Bool("h", false, "This massage")
	VERSION = "0.4.0"
)

func argsUsage() {
	fmt.Println(`GoRootCheck - OSSEC Standalone RootCheck in GO
v` + VERSION + ` - github.com/pyperanger/gorootcheck
`)
}

func Args() bool {
	argsUsage()
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
