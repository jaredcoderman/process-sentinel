package processmanager

import (
	"fmt"
	"process-sentinel/chaindetector"

	"github.com/shirou/gopsutil/v3/process"
)

func GetProcesses() ([]*process.Process, map[int32]*process.Process, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, nil, err
	}
	parentMap := make(map[int32]*process.Process)
	for _, p := range procs {
		parentMap[p.Pid] = p
	}
	return procs, parentMap, nil
}

func BuildProcessChain(p *process.Process, parentMap map[int32]*process.Process) ([]string, error) {
	var chain []string
	current := p
	for i := 0; i < 6; i++ {
		name, err := current.Name()
		if err != nil {
			return nil, err
		}
		ppid, err := current.Ppid()
		if err != nil {
			return nil, err
		}
		parent, ok := parentMap[ppid]
		if !ok {
			break
		}
		parentName, err := parent.Name()
		if err != nil {
			return nil, err
		}
		if name != parentName {
			chain = append([]string{name}, chain...)
		}
		current = parent
	}
	return chain, nil
}

func CheckProcesses() error {
	procs, parentMap, err := GetProcesses()
	if err != nil {
		return err
	}

	for _, p := range procs {
		chain, err := BuildProcessChain(p, parentMap)
		if err != nil {
			return err
		}

		if isSuspicious, severity := chaindetector.CheckChain(chain); isSuspicious {
			fmt.Println("SUSPICIOUS CHAIN: ", chain, " SEVERITY: ", severity)
		}

	}
	return nil
}
