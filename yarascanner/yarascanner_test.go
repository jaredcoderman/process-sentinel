package yarascanner

import (
	"os"
	"testing"
)

func TestYaraRuleMatching(t *testing.T) {
	// Create a temporary rule file
	ruleContent := `
rule ContainsHello {
	strings:
		$h = "hello"
	condition:
		$h
}`
	rulePath := "test_rule.yar"
	err := os.WriteFile(rulePath, []byte(ruleContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write rule file: %v", err)
	}
	defer os.Remove(rulePath)

	// Create a test file to scan
	testFile := "test_sample.txt"
	err = os.WriteFile(testFile, []byte("this contains hello"), 0644)
	if err != nil {
		t.Fatalf("Failed to write sample file: %v", err)
	}
	defer os.Remove(testFile)

	// Initialize rules
	err = Init(rulePath)
	if err != nil {
		t.Fatalf("Failed to initialize yara rules: %v", err)
	}

	// Scan file
	matches, err := ScanFile(testFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	found := false
	for _, m := range matches {
		if m == "ContainsHello" {
			found = true
		}
	}

	if !found {
		t.Errorf("Expected rule 'ContainsHello' to match, but it didn't")
	}
}
