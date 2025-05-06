package main

import (
	"fmt"
	"path/filepath"
	"process-sentinel/chaindetector"
	"process-sentinel/yarascanner"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	err := yarascanner.Init("rules/exe_rules.yar")
	if err != nil {
		panic(fmt.Sprintf("❌ Failed to init YARA: %v", err))
	}

	a := app.New()
	w := a.NewWindow("Process Sentinel")

	output := widget.NewMultiLineEntry()
	output.SetPlaceHolder("Results will appear here...")
	output.Wrapping = fyne.TextWrapWord
	scroll := container.NewVScroll(output)

	runButton := widget.NewButton("Run Chain Scan Demo", func() {
		output.SetText("")

		fakeChains := [][]string{
			{"winword.exe", "powershell.exe"},
			{"excel.exe", "cmd.exe", "powershell.exe"},
			{"explorer.exe", "notepad.exe"},
			{"outlook.exe", "foo.exe", "mshta.exe"},
		}

		for _, chain := range fakeChains {
			isSuspicious, severity := chaindetector.CheckChain(chain)
			line := fmt.Sprintf("CHAIN: %v → Suspicious: %v (Severity: %s)\n", chain, isSuspicious, severity)

			if isSuspicious {
				last := strings.ToLower(chain[len(chain)-1])
				path := filepath.Join("samples", last)

				matches, err := yarascanner.ScanFile(path)
				if err != nil {
					line += fmt.Sprintf("⚠️  Scan error: %v\n", err)
				} else if len(matches) > 0 {
					line += fmt.Sprintf("🚨 Matches in %s: %v\n", path, matches)
				} else {
					line += fmt.Sprintf("✅ No YARA matches in %s\n", path)
				}
			}

			output.SetText(output.Text + line + "\n")
			scroll.ScrollToBottom()
		}
	})

	top := container.NewVBox(
		widget.NewLabel("🔍 Process Chain Scanner Demo"),
		runButton,
	)

	content := container.NewBorder(top, nil, nil, nil, scroll)

	w.SetContent(content)
	w.Resize(fyne.NewSize(700, 500))
	w.ShowAndRun()
}
