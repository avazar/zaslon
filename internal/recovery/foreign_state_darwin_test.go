package recovery

import "golang.org/x/sys/unix"

func fixtureStopped(pid int) (bool, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return false, err
	}
	return kp != nil && kp.Proc.P_stat == 4, nil // SSTOP
}
