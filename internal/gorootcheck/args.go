package gorootcheck

import (
	"flag"
	"fmt"
)

var (
	workdir = flag.String("w", "./", "Path with database datails and signatures")
	version = flag.Bool("version", false, "Show version")
	debug = flag.Bool("v", false, "Debug mode")
	help = flag.Bool("h", false, "This massage")
)

func argsUsage() {
	fmt.Println(`GoRootCheck - OSSEC Standalone RootCheck in GO
v0.1.0 - github.com/pyperanger/gorootcheck
`)
}

func Args() bool {
	argsUsage()
	flag.Parse()
	if *help {
		flag.Usage()
		bye()
	}

	if !dirExist(*workdir) {
		fmt.Println(*workdir, ": Not found")
		return false
	}

	if !dbCheck(*workdir) 

	return true
}