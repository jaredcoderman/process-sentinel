package main

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

func main() {
	for {
		processes, error := process.Processes()
		if error != nil {
			fmt.Println(error)
		}

		parentMap := make(map[int32]string)
		for _, p := range processes {
			name, err := p.Name()
			if err == nil {
				parentMap[p.Pid] = name
			}
		}

		for _, p := range processes {
			name, err := p.Name()
			if err != nil {
				continue
			}
			ppid, _ := p.Ppid()
			parentName := parentMap[ppid]

			fmt.Printf("PID: %d | PPID: %d | Name: %s | Parent: %s\n", p.Pid, ppid, name, parentName)

			if name == "powershell.exe" && parentName == "winword.exe" {
				fmt.Println("🚨 SUSPICIOUS: powershell.exe spawned by winword.exe")
			}
		}
		time.Sleep(2 * time.Second)
	}

}
