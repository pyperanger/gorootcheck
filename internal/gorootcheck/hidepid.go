/*
	Rule #5 code - Hidden Processes

#5  Look for the presence of hidden processes. We use getsid()
and kill() to check if any pid is being used or not. If the pid
is being used, but “ps” can’t see it, it is the indication of
kernel-level rootkit or a trojaned version of “ps”. We also
verify that the output of kill and getsid are the same.

Binaries: ps
*/
package gorootcheck

import (
	"syscall"
	"fmt"
	"os/exec"
	"strings"
)

var (
	maxpid = 419430
)

// Find all alive pid based kill 0 signal
func syskillzero() []int{
	var pids []int
	for i := 1; i < maxpid ; i++ {
		err := syscall.Kill(i, syscall.Signal(0))
		if err == syscall.EPERM {
			pids = append(pids, i)
		}
	}
	return pids
}

// PS AUX command return
// pipe to avoid false positives
func stdpsaux() string {
	ps := exec.Command("ps", "auxf")
	awk := exec.Command("awk", "{print $2}")

	pipe, err := ps.StdoutPipe()
	if err != nil {
		return ""
	}
	awk.Stdin = pipe

	err = ps.Start()
	if err != nil {
		return ""
	}
	
	std, err := awk.Output()
	if err != nil {
		return ""
	}
	return string(std)
}

// Main rule #5 function
func hidden_pid() {
	fmt.Println("#5 - Searching for hidden processes")
	spid := syskillzero()
	ps := stdpsaux()
	if ps == "" {
		fmt.Println(" :(\t [ ps aux ] command error")
	}

	// Filter string format 
	psaux := strings.Split(ps, "\n")[1:]
	
	if len(psaux) != len(spid) {
		// Investigate based syskill values
		fmt.Println(" - Possible hidden process in system [ rootkit, binary patch, LD_PRELOAD ]")
		fmt.Println("SYS: ", len(spid), "\nPS: ", len(psaux))
	}
}