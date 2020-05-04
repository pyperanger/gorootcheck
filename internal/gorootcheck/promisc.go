/*
	Rule #7 code - Promisc mode
#7 Scan all interfaces on the system and look
for the ones with “promisc” mode enabled.
If the interface is in promiscuous mode, the
output of “ifconfig” should show that. If not,
we probably have a rootkit installed.

file:
	/sys/class/net/<iface>/flags

ref: 
	https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net
	https://github.com/torvalds/linux/blob/master/include/uapi/linux/if.h
*/
package gorootcheck

import (
	"fmt"
	"regexp"
	"strconv"
	"io/ioutil"
	"os/exec"
)

// return all interfaces name
func listinterfaces() ([]string, error) {
	var iface []string
	ifacedirs, err := ioutil.ReadDir("/sys/class/net/")
	if err != nil {
		return nil, err
	}
	for _, i := range ifacedirs {
		iface = append(iface, i.Name())
	}
	return iface, nil 
}

// return TRUE if given interface is in promisc mode
// promisc mode bitmask 100
func scaninterface(iface string) bool {
	flags, err := ioutil.ReadFile("/sys/class/net/"+iface+"/flags")
	if err != nil {
		fmt.Println(" - Error reading flags from interface: ", iface)
		return false
	}
	bytemark := flags[2:len(flags)-1]
	if len(bytemark) < 3 {
		return false
	}
	bitmark, err := strconv.Atoi(string(bytemark))
	if err != nil {
		return false
	}
	if bitmark / 100 == 11 || bitmark / 100 == 1 {
		return true
	}
	return false
}

// return TRUE if interface is promisc mode 
// in ifconfig command
func ifconfigface(iface string) bool {
	cmd := exec.Command("ifconfig", iface)
	stdconfig, err := cmd.Output()
	if err != nil {
		return false
	}
	promisc, _ := regexp.Compile("PROMISC")
	if promisc.MatchString(string(stdconfig)) {
		return true
	}
	return false
}

func promisc() {
	fmt.Println("#7 - Searching for hidden promisc interfaces")
	ifaces, err := listinterfaces()
	if err != nil {
		panic(err)
	}
	for _, i := range ifaces {
		if scaninterface(i) && !ifconfigface(i) {
			fmt.Println("\t- Interface in hidden promisc mode: ", i)
		}
	}
}