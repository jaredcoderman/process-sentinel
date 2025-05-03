package chaindetector

var suspiciousChains = [][]string{
	{"winword.exe", "powershell.exe"},
	{"excel.exe", "cmd.exe", "powershell.exe"},
	{"outlook.exe", "mshta.exe"},
}

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
	patternIndex := 0
	for chainIndex := range chain {
		if chain[chainIndex] == pattern[patternIndex] {
			patternIndex++
		}
		if patternIndex == len(pattern) {
			return true
		}
	}
	return false
}
