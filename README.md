This is a **'free time'** project, for study propose only.

# gorootcheck
[![https://travis-ci.com/github/pyperanger/gorootcheck](https://api.travis-ci.com/pyperanger/gorootcheck.svg?branch=master&status=passed)](https://travis-ci.com/github/pyperanger/gorootcheck)<br>
Standalone rootcheck by **OSSEC** wrtitten in Go

#### 2020-19-05 | v0.7.0 - Persist Issues
- Rule #1 Some false positives(**rootkit_files.txt**) and bugs persist
- Rule #3 bypasses issues
- Rule #5 false positives(delivery by some race conditions)


### Install 
```
git clone https://github.com/pyperanger/gorootcheck.git
cd gorootcheck
make
```

https://www.ossec.net/docs/manual/rootcheck/manual-rootcheck.html
### Rootcheck features  
 - [X] Read the rootkit_files.txt which contains a database of rootkits and files commonly used by them. It will try to stats, fopen and opendir each specified file. We use all these system calls because some kernel-level rootkits hide files from some system calls. The more system calls we try, the better the detection. This method is more like an anti-virus rule that needs to be updated constantly. The chances of false-positives are small, but false negatives can be produced by modifying the rootkits.
 - [ ] Read the rootkit_trojans.txt which contains a database of signatures of files trojaned by rootkits. This technique of modifying binaries with trojaned versions was commonly used by most of the popular rootkits available. This detection method will not find any kernel level rootkit or any unknown rootkit.
 - [X] Scan the /dev directory looking for anomalies. The /dev should only have device files and the Makedev script. A lot of rootkits use the /dev to hide files. This technique can detect even non-public rootkits.
- [X] Scan the whole filesystem looking for unusual files and permission problems. Files owned by root, with write permission to others are very dangerous, and the rootkit detection will look for them. Suid files, hidden directories and files will also be inspected.
- [X] Look for the presence of hidden processes. We use getsid() and kill() to check if any pid is being used or not. If the pid is being used, but “ps” can’t see it, it is the indication of kernel-level rootkit or a trojaned version of “ps”. We also verify that the output of kill and getsid are the same.
- [X] [IPV4/IPV6] Look for the presence of hidden ports. We use bind() to check every tcp and udp port on the system. If we can’t bind to the port (it’s being used), but netstat does not show it, we probably have a rootkit installed
- [X] Scan all interfaces on the system and look for the ones with “promisc” mode enabled. If the interface is in promiscuous mode, the output of “ifconfig” should show that. If not, we probably have a rootkit installed.

### Bonus features

- [ ] TheHive Integration Alert
- [ ] Yara Rules
- [ ] MISP
- [ ] JSON HTTP/REST Report

#### BUGS OR BYPASS(Coool)
Open a issue or contact me pype@0day.rocks via xmpp
