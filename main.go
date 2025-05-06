package main

import (
	"fmt"
	"log"
	"path/filepath"
	"process-sentinel/chaindetector"
	"process-sentinel/yarascanner"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func main() {

	// Load YARA rules
	err := yarascanner.Init("rules/exe_rules.yar")
	if err != nil {
		panic(fmt.Sprintf("❌ Failed to init YARA: %v", err))
	}

	// Load Suspicious Chains
	err = chaindetector.LoadChainsFromFile("data/suspicious_chains.txt")
	if err != nil {
		log.Printf("⚠️ Failed to load chain patterns: %v (using defaults)\n", err)
	}

	a := app.New()
	w := a.NewWindow("Process Sentinel")

	output := widget.NewMultiLineEntry()
	output.SetPlaceHolder("Results will appear here...")
	output.Wrapping = fyne.TextWrapWord
	scroll := container.NewVScroll(output)

	runButton := widget.NewButton("🤖 Run Chain Scan Demo", func() {
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

	scanFileButton := widget.NewButton("📁 Scan File", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			path := reader.URI().Path()
			output.SetText(fmt.Sprintf("📁 Scanning file: %s\n", path))

			matches, err := yarascanner.ScanFile(path)
			if err != nil {
				output.SetText(output.Text + fmt.Sprintf("⚠️ Scan error: %v\n", err))
			} else if len(matches) > 0 {
				output.SetText(output.Text + fmt.Sprintf("🚨 Matches found: %v\n", matches))
			} else {
				output.SetText(output.Text + "✅ No YARA matches found.\n")
			}
		}, w)
	})

	editChainsButton := widget.NewButton("⚙️ Edit Chains", func() {
		chains, err := chaindetector.GetChains()
		if err != nil {
			log.Printf("⚠️ Failed on chaindetector.GetChains()")
		}
		newOutputText := ""
		for _, chain := range chains {
			for i := 0; i < len(chain); i++ {
				newOutputText += chain[i]
				if i < len(chain)-1 {
					newOutputText += ","
				}
			}
			newOutputText += "\n"
		}
		output.SetText(newOutputText)
	})

	saveButton := widget.NewButton("Save", func() {
		text := output.Text
		chaindetector.UpdateChains(text)
	})

	top := container.NewVBox(
		widget.NewLabel("🖥️ Process Sentinel Dashboard"),
		container.NewHBox(runButton, scanFileButton, editChainsButton, saveButton), // Two buttons side by side
	)

	content := container.NewBorder(top, nil, nil, nil, scroll)

	w.SetContent(content)
	w.Resize(fyne.NewSize(700, 500))
	w.ShowAndRun()
}
