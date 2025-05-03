# 🛡️ Process Sentinel

**Process Sentinel** is a lightweight Go-based process monitoring tool designed to detect suspicious parent-child process chains commonly associated with Living Off The Land Binaries (LOLBins) and malicious activity on Windows systems.

## 🚀 Features

- 🧠 Detects known suspicious process chains (e.g. `winword.exe → powershell.exe`)
- 🔎 Classifies matches by severity: `HIGH`, `MEDIUM`, or `NONE`
- 🧬 Supports both exact and subsequence-based matching
- 🔁 Runs in a loop, checking the system every 2 seconds
- ✅ Includes unit tests for core detection logic

## 🔧 How It Works

The system builds process chains using live process data and checks them against a set of known suspicious patterns:

- **Exact Match**: The full sequence matches (e.g. `excel.exe → cmd.exe → powershell.exe`)
- **Subsequence Match**: The pattern appears in order but with potential noise in between (e.g. `outlook.exe → [random] → mshta.exe`)

All process chains are checked using `chaindetector.CheckChain(chain)` which returns:
- A boolean indicating if the chain is suspicious
- A severity level

## 📁 Project Structure

```
process-sentinel/
├── main.go # App entry point
├── processmanager/ # Builds and manages process chains
│ └── logic.go
├── chaindetector/ # Detection engine
│ ├── detector.go # Contains detection logic
│ └── chaindetector_test.go # Unit tests for detection logic
```
## 🧪 Running Tests

Make sure you're in the project root (where `go.mod` is), then run:

```bash
go test ./...
```
## 🛠 Future Ideas
📝 Logging to Splunk or another SIEM

🌐 Detecting suspicious network activity per process

🧩 Plugin system for additional behavioral checks

🪪 Signature-based exceptions or allow-listing
