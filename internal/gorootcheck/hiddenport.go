/*
	Rule #6 code - Hidden Listen Port
#6	Look for the presence of hidden ports. We use bind()
to check every tcp and udp port on the system. If we
can’t bind to the port (it’s being used), but netstat
does not show it, we probably have a rootkit installed

Check TCP/UDP ports

[X] TCP
[ ] UDP

*/
package gorootcheck

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// Return TRUE is NOT FOUND port in output
func inssstd(std string, port int) bool {
	ss := strings.Split(std, "\n")
	spgex, _ := regexp.Compile(`(?m)(\d+$)`)
	for _, p := range ss[1:len(ss)-1] {
		ssport, err := strconv.Atoi(spgex.FindString(p))
		if err != nil {
			return false
		}
		if ssport == port {
			return false
		}
	}
	return true
}

func closefd(fd int) {
	if err := syscall.Close(fd); err != nil {
		return
	}
}

// Execute `ss` command
// protocol -> t[cp] or u[dp]
func inss(protocol string, port int) bool {
	ss := exec.Command("ss", "-l", protocol, "-n")
	awk := exec.Command("awk", "{print $4}")
	pipe, err := ss.StdoutPipe()
	if err != nil {
		return false
	}
	awk.Stdin = pipe
	err = ss.Start()
	if err != nil {
		return false
	}
	std, err := awk.Output()
	if err != nil {
		return false
	}
	
	if inssstd(string(std), port) {
		return true
	}
	return false
}

// Check if TCP port is already in use
func tcpssport(port int) bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.O_NONBLOCK|syscall.SOCK_STREAM, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	if err = syscall.SetNonblock(fd, true); err != nil {
		return false
	}
	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], net.ParseIP("0.0.0.0").To4())

	if err = syscall.Bind(fd, &addr); err != nil {
		if inss("-t", port) {
			closefd(fd)
			return true
		}
	}
	closefd(fd)
	return false
}

// Check if UDP port is already in use
func udpssport(port int) bool {
	pc, err := net.ListenPacket("udp", ":" + strconv.Itoa(port))
	if err != nil {
		if inss("-u", port) {
			return true
		}
		return false // invalid memory address or nil pointer dereference
	}
	defer pc.Close()
	return false
}

func hidden_port() {
	fmt.Println("#6 - Searching for hidden ports [ TCP/UDP - IPV4/IPV6 ]")
	for i := 0; i <= 65535; i++ {
		if tcpssport(i) {
			fmt.Println("\t- Hidden TCP Port: ", i)
		}
		if udpssport(i) {
			fmt.Println("\t- Hidden UDP Port: ", i)
		}
	}
}