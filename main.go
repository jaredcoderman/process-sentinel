package main

import (
	"fmt"
	"log"
	"process-sentinel/chaindetector"
	"process-sentinel/splunklogger"
)

func main() {
	fakeChains := [][]string{
		{"winword.exe", "powershell.exe"},          // suspicious (HIGH)
		{"excel.exe", "cmd.exe", "powershell.exe"}, // suspicious (HIGH)
		{"explorer.exe", "notepad.exe"},            // normal
		{"outlook.exe", "foo.exe", "mshta.exe"},    // suspicious (MEDIUM)
	}

	for _, chain := range fakeChains {
		isSuspicious, severity := chaindetector.CheckChain(chain)

		fmt.Printf("CHAIN: %v → Suspicious: %v (Severity: %s)\n", chain, isSuspicious, severity)

		if isSuspicious {
			err := splunklogger.SendToSplunk(map[string]interface{}{
				"chain":    chain,
				"severity": severity,
				"note":     "Demo event from main.go",
			})
			if err != nil {
				log.Printf("❌ Failed to log chain %v: %v\n", chain, err)
			} else {
				log.Printf("✅ Logged chain %v with severity %s\n", chain, severity)
			}
		}
	}
}
