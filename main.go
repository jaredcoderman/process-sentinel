package main

import (
	"fmt"
	"log"
	"process-sentinel/processmanager"
	"time"
)

func main() {

	for {
		procs, parentMap, err := processmanager.GetProcesses()
		if err != nil {
			log.Fatal(err)
		}

		for _, p := range procs {
			processChain, err := processmanager.BuildProcessChain(p, parentMap)
			if err != nil {
				log.Printf("error building process chain for PID %d: %v", p.Pid, err)
				continue
			}
			fmt.Println(processChain)
		}

		time.Sleep(2 * time.Second)
	}

}
