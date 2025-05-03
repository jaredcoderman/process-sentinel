package main

import (
	"process-sentinel/processmanager"
	"time"
)

func main() {
	for {
		processmanager.CheckProcesses()
		time.Sleep(2 * time.Second)
	}
}
