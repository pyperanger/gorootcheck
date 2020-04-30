/*
	Rule #5 code - Hidden Processes

#5  Look for the presence of hidden processes. We use getsid()
and kill() to check if any pid is being used or not. If the pid
is being used, but “ps” can’t see it, it is the indication of
kernel-level rootkit or a trojaned version of “ps”. We also
verify that the output of kill and getsid are the same.

Binaries: ps, ls /proc, lsof -pid ? 
..
*/
package gorootcheck

import (
	"syscall"
	"fmt"
	"strconv"
	"os/exec"
	//"strings"
)

var (
	maxpid = 419430
)

// Find all alive pid based kill 0 signal
func syskillzero() []int{
	var pids []int
	for i := 1; i < maxpid ; i++ {
		err := syscall.Kill(i, syscall.Signal(0))
		if err == nil {
			pids = append(pids, i)
		}
		
	}
	return pids
}

// PS AUX command return
// pipe to avoid false positives
func lsproc() string {
	ls := exec.Command("ls", "/proc")
	
	std, err := ls.Output()
	if err != nil {
		return ""
	}
	return string(std)
}

// ps -eT | awk '{print $1}' | grep -w 37
// Check pid hidden from ps command 
func psfind(pid int) bool {
	ps := exec.Command("ps","--no-header","-p",strconv.Itoa(pid),"o","pid")
	std, err := ps.Output()
	if err != nil {
		fmt.Println("Hidden PID: ", strconv.Itoa(pid))
		return false
	}
	if string(std) == "" {
		fmt.Println("Hidden PID: ", strconv.Itoa(pid))
	}
	return true
}

// proc
func psproc() {
	var pids []int
	//var hpids []int
	for i := 1; i <= maxpid; i++ {
		if dirExist("/proc/"+strconv.Itoa(i)) {
			if psfind(i) {
				pids = append(pids, i)
			}
		}
	}
	//fmt.Println("All Pids: ", pids, "\nHidden Pids: ", hpids)
}


// Main rule #5 function
func hidden_pid() {
	fmt.Println("#5 - Searching for hidden processes")
	// /proc with native os.Stat
	psproc()
}