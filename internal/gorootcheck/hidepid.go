/*
	Rule #5 code - Hidden Processes

#5  Look for the presence of hidden processes. We use getsid()
and kill() to check if any pid is being used or not. If the pid
is being used, but “ps” can’t see it, it is the indication of
kernel-level rootkit or a trojaned version of “ps”. We also
verify that the output of kill and getsid are the same.
..
*/
package gorootcheck

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"regexp"
	"strings"
	"syscall"
)

// check if given pid/lwp is
// a possible thread of gorootkit pid
func islwp(grk int, pid int) bool {
	status, err := fileReadline("/proc/"+ strconv.Itoa(pid) + "/status")
	if err != nil {
		return false
	}
	tgex, _ := regexp.Compile(`(?m)(\S+$)`)
	tgid, err := strconv.Atoi(tgex.FindString(status[2]))
	if err != nil {
		return false
	}
	if grk == tgid{
		return true
	}
	return false
}

// Get system max pid
// /proc/sys/kernel/pid_max
func pidmax() int {
	pm, err := fileReadline("/proc/sys/kernel/pid_max")
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(pm[0])
	if err != nil {
		return 0
	}
	return p
}

// SHOW PID INFO
func pidinfo(pid int) {
	piddir := "/proc/" + strconv.Itoa(pid)
	cmd, err := fileReadline(piddir + "/cmdline")
	if err != nil {
		return
	}
	cwd, err := os.Readlink(piddir + "/cwd")
	if err != nil {
		return
	}
	exe, err := os.Readlink(piddir + "/exe")
	if err != nil {
		return
	}
	fmt.Println("\tCMDLINE => ", cmd[0], "\n\tBinary => ", exe, "\n\tPWD => ", cwd )
}

// Kill -0 $PID
func syskillzero(pid int) bool {
	err := syscall.Kill(pid, syscall.Signal(0))
	if err != nil {
		return false
	}
	return true
}

// Filter psfind returned value
// and find given pid
// return true if a pid it NOT founded 
// in PS output 
func psfindstd(out string, pid int) bool {
	stdlite := strings.Split(out, "\n")
	for _, v := range stdlite {
		vp := strings.Replace(v, " ", "", -1)
		vv, _ := strconv.Atoi(vp)
		if vv == pid {
			return false
		}
	}
	return true
}

// ps -eT | awk '{print $1}' | grep -w 37
// Check pid hidden from ps command
func psfind(pid int) bool {
	ps := exec.Command("ps", "--no-header", "-eL", "o", "lwp")
	std, err := ps.Output()
	if err != nil {
		return false
	}
	if psfindstd(string(std), pid) {
		return true
	}
	return false
}

// Use native golang os.Stat to check
// /proc/[pids]
func psproc() {
	var pids []int
	maxpid := pidmax()

	if maxpid == 0 {
		fmt.Println(" Error: /proc/sys/kernel/pid_max")
		return
	}

	for i := 1; i <= maxpid; i++ {
		if i == os.Getpid() {
			continue
		}
		if dirExist("/proc/" + strconv.Itoa(i)) {
			if psfind(i) {
				if !islwp(os.Getpid(), i) {
					pids = append(pids, i)
				}
			}
		}
	}
	// Here some false positives can be avoided
	// but hit the heart of performance :c
	for _, pid := range pids {
		if dirExist("/proc/" + strconv.Itoa(pid)) {
			if syskillzero(pid) {
				fmt.Println("	- Hidden PID:", pid)
				pidinfo(pid)
			}
		}
	}
	//fmt.Println("All Pids: ", pids, "\nHidden Pids: ", hpids)
}

// Main rule #5 function
func hidden_pid() {
	fmt.Println("#5 - Searching for hidden processes [ rootkit/binaries patch ]")
	// /proc with native os.Stat
	psproc()
}
