# 🛡️ Process Sentinel

**Process Sentinel** is a lightweight Go-based process monitoring tool designed to detect suspicious parent-child process chains commonly associated with LOLBins and malicious activity on Windows systems.

## Features

- Detects known suspicious process chains (e.g. `winword.exe → powershell.exe`)
- Classifies matches by severity: `HIGH`, `MEDIUM`, or `NONE`
- Supports both exact and subsequence-based matching
- Periodically scans the system every 2 seconds
- Forwards suspicious activity logs to a local Splunk HTTP Event Collector (HEC)
- Includes unit tests for core detection logic

## How It Works

The system builds parent-child process chains using live data and checks them against a list of known suspicious patterns.

- **Exact Match**: Full sequence matches (e.g. `excel.exe → cmd.exe → powershell.exe`)
- **Subsequence Match**: The pattern appears in order but with other processes in between (e.g. `outlook.exe → [unknown] → mshta.exe`)

When a suspicious chain is found, `chaindetector.CheckChain(chain)` returns:

- A boolean indicating if the chain is suspicious
- A severity level

If suspicious, the chain is also sent to Splunk via its HTTP Event Collector.

## Project Structure
```bash
process-sentinel/  
├── main.go                    # Entry point for demo / usage  
├── processmanager/  
│   ├── logic.go               # Builds and analyzes live process trees  
│   └── logic_test.go          # Unit tests (with fake process chains)  
├── chaindetector/  
│   ├── detector.go            # Pattern-matching logic  
│   └── chaindetector_test.go  # Tests for chain detection  
├── splunklogger/  
│   └── logger.go              # Sends matched events to Splunk  
├── .env                       # Contains Splunk HEC token and config  
```
## Running the Demo

1. Ensure Splunk is running locally with an active HTTP Event Collector (HEC) on port 8088.  
2. Create a `.env` file in the project root with the following values:

SPLUNK_URL=https://localhost:8088  
SPLUNK_TOKEN=your-splunk-hec-token  

3. Run the demo:
```bash
go run main.go
```
This will simulate a few process chains and log any suspicious ones to Splunk.

## Running Tests

Make sure you're in the project root (where `go.mod` is), then run:
```bash
go test ./...
```
## Future Ideas

- Detecting suspicious network activity per process  
- Plugin system for additional behavioral checks  
- Signature-based exceptions or allow-listing  
- Logging to other SIEMs or file-based fallback  

## License

MIT License
