package yarascanner

import (
	"fmt"
	"os"
	"time"

	"github.com/hillu/go-yara/v4"
)

var rules *yara.Rules

func Init(rulePath string) error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	rf, err := os.Open(rulePath)
	if err != nil {
		return err
	}
	defer rf.Close()

	err = compiler.AddFile(rf, "")
	if err != nil {
		return err
	}

	rules, err = compiler.GetRules()
	if err != nil {
		return err
	}

	fmt.Println("✅ Loaded rules from file:", rulePath)
	return nil
}

type matchCollector struct {
	matches []string
}

func (m *matchCollector) RuleMatching(ctx *yara.ScanContext, r *yara.Rule) (bool, error) {
	fmt.Println("📌 YARA matched rule:", r.Identifier()) // ADD THIS
	m.matches = append(m.matches, r.Identifier())
	return true, nil
}

func (m *matchCollector) RuleNotMatching(ctx *yara.ScanContext, r *yara.Rule) (bool, error) {
	return true, nil
}

func (m *matchCollector) ScanFinished() error { return nil }
func (m *matchCollector) ScanStarting() error { return nil }

func (m *matchCollector) ImportModule(name string) ([]byte, error) {
	return nil, fmt.Errorf("module imports not supported")
}

func ScanFile(path string) ([]string, error) {
	fmt.Printf("Scanning file %s\n", path)
	collector := &matchCollector{}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read error: %v", err)
	}

	err = rules.ScanMem(data, 0, 5*time.Second, collector)
	if err != nil {
		return nil, fmt.Errorf("scan error: %v", err)
	}

	return collector.matches, nil
}
