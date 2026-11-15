package recovery

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func fixtureStopped(pid int) (bool, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false, err
	}
	fields := strings.Fields(string(b)[strings.LastIndexByte(string(b), ')')+1:])
	if len(fields) == 0 {
		return false, fmt.Errorf("empty fixture state")
	}
	return fields[0] == "T" || fields[0] == "t", nil
}
