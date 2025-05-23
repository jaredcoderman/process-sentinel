package chaindetector

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strings"
)

var suspiciousChains = [][]string{}

func CheckChain(chain []string) (bool, string) {
	for _, pattern := range suspiciousChains {
		if containsExactPattern(chain, pattern) {
			return true, "HIGH"
		}
		if containsSubSequence(chain, pattern) {
			return true, "MEDIUM"
		}
	}
	return false, "NONE"
}

func IsValidChainInput(s string) bool {
	re := regexp.MustCompile(`^([a-zA-Z0-9_.-]+)(,[a-zA-Z0-9_.-]+)*$`)
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue // skip blank lines
		}
		if !re.MatchString(line) {
			return false
		}
	}
	return true
}

func UpdateChains(newChainsString string) error {
	if !IsValidChainInput(newChainsString) {
		return errors.New("invalid format: each line must be comma-separated process names")
	}

	chains := strings.Split(newChainsString, "\n")

	var newChains [][]string
	for _, chain := range chains {
		processes := strings.Split(chain, ",")
		newChains = append(newChains, processes)
	}
	err := os.WriteFile("data/suspicious_chains.txt", []byte(newChainsString), 0644)
	if err != nil {
		return err
	}
	print("Updating suspicious chains")
	suspiciousChains = newChains
	return nil
}

func GetChains() ([][]string, error) {
	return suspiciousChains, nil
}

func LoadChainsFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var loadedChains [][]string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		processes := strings.Split(line, ",")
		for i := range processes {
			processes[i] = strings.TrimSpace(processes[i])
		}
		loadedChains = append(loadedChains, processes)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	suspiciousChains = loadedChains
	return nil
}

func containsExactPattern(chain []string, pattern []string) bool {
	if len(chain) < len(pattern) {
		return false
	}
	for i := 0; i <= len(chain)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if chain[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func containsSubSequence(chain []string, pattern []string) bool {
	pIndex := 0
	for _, proc := range chain {
		if proc == pattern[pIndex] {
			pIndex++
			if pIndex == len(pattern) {
				return true
			}
		}
	}
	return false
}

// BELOW IS OVER-ENGINEERING WORK IN PROGRESS
type TrieNode struct {
	children   map[string]*TrieNode
	fail       *TrieNode
	isTerminal bool
	patterns   [][]string
}

func insert(root *TrieNode, pattern []string) {
	node := root
	for _, process := range pattern {
		if node.children[process] == nil {
			node.children[process] = &TrieNode{
				children: make(map[string]*TrieNode),
			}
			node = node.children[process]
		}
		node = node.children[process]
	}
	node.isTerminal = true
	node.patterns = append(node.patterns, pattern)
}

func buildFailureLinks(root *TrieNode) {
	queue := []*TrieNode{}

	for _, child := range root.children {
		child.fail = root
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for process, child := range root.children {
			fallback := current.fail
			for fallback != nil && fallback.children[process] == nil {
				fallback = fallback.fail
			}

			if fallback != nil {
				child.fail = fallback.children[process]
			} else {
				child.fail = root
			}

			if child.fail.isTerminal {
				child.patterns = append(child.patterns, child.fail.patterns...)
			}

			queue = append(queue, child)
		}
	}
}
