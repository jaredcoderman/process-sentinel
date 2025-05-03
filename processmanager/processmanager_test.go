package processmanager

import (
	"process-sentinel/chaindetector"
	"testing"
)

type FakeProcess struct {
	Pid  int32
	Name string
	PPid int32
}

func buildFakeChain(p *FakeProcess, processMap map[int32]*FakeProcess) []string {
	var chain []string
	current := p
	for i := 0; i < 6; i++ {
		if current == nil {
			break
		}
		chain = append([]string{current.Name}, chain...)
		current = processMap[current.PPid]
	}
	return chain
}

func TestCheckChain_DetectsSuspicious(t *testing.T) {
	processes := map[int32]*FakeProcess{
		100: {Pid: 100, Name: "powershell.exe", PPid: 99},
		99:  {Pid: 99, Name: "winword.exe", PPid: 1},
	}

	chain := buildFakeChain(processes[100], processes)
	isSuspicious, severity := chaindetector.CheckChain(chain)

	if !isSuspicious {
		t.Errorf("Expected chain %v to be suspicious, got not suspicious", chain)
	}
	if severity != "HIGH" {
		t.Errorf("Expected severity HIGH, got %s", severity)
	}
}

func TestCheckChain_NonSuspicious(t *testing.T) {
	processes := map[int32]*FakeProcess{
		200: {Pid: 200, Name: "notepad.exe", PPid: 150},
		150: {Pid: 150, Name: "explorer.exe", PPid: 1},
	}

	chain := buildFakeChain(processes[200], processes)
	isSuspicious, severity := chaindetector.CheckChain(chain)

	if isSuspicious {
		t.Errorf("Expected chain %v to be not suspicious, but was flagged", chain)
	}
	if severity != "NONE" {
		t.Errorf("Expected severity NONE, got %s", severity)
	}
}
