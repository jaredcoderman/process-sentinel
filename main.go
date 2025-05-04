package main

import (
	"fmt"
	"log"
	"path/filepath"
	"process-sentinel/chaindetector"
	"process-sentinel/splunklogger"
	"process-sentinel/yarascanner"
	"strings"
)

func main() {
	err := yarascanner.Init("rules/test_rule.yar")
	if err != nil {
		log.Fatalf("❌ Failed to initialize YARA: %v", err)
	}

	fakeChains := [][]string{
		{"winword.exe", "powershell.exe"},
		{"excel.exe", "cmd.exe", "powershell.exe"},
		{"explorer.exe", "notepad.exe"},
		{"outlook.exe", "foo.exe", "mshta.exe"},
	}

	for _, chain := range fakeChains {
		isSuspicious, severity := chaindetector.CheckChain(chain)

		fmt.Printf("CHAIN: %v → Suspicious: %v (Severity: %s)\n", chain, isSuspicious, severity)

		if isSuspicious {
			last := chain[len(chain)-1]
			lastExe := strings.ToLower(last)
			samplePath := filepath.Join("samples", lastExe)

			yaraMatches, err := yarascanner.ScanFile(samplePath)
			fmt.Println("YARA Matches: ", yaraMatches)
			if err != nil {
				log.Printf("⚠️ Could not scan %s with YARA: %v", samplePath, err)
			} else if len(yaraMatches) > 0 {
				log.Printf("🚨 YARA matched %s: %v", samplePath, yaraMatches)
			} else {
				log.Printf("✅ YARA found nothing in %s", samplePath)
			}

			logData := map[string]interface{}{
				"chain":        chain,
				"severity":     severity,
				"note":         "Demo event from main.go",
				"yara_matches": yaraMatches,
				"scanned_file": samplePath,
			}

			err = splunklogger.SendToSplunk(logData)
			// if err != nil {
			// 	log.Printf("❌ Failed to log chain %v: %v\n", chain, err)
			// } else {
			// 	log.Printf("✅ Logged chain %v with severity %s\n", chain, severity)
			// }
		}
	}
}
