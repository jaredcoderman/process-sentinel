package chaindetector

import "testing"

func TestContainsExactPattern(t *testing.T) {
	tests := []struct {
		name    string
		chain   []string
		pattern []string
		expect  bool
	}{
		{
			name:    "exact match at end",
			chain:   []string{"a", "b", "c"},
			pattern: []string{"b", "c"},
			expect:  true,
		},
		{
			name:    "exact match in middle",
			chain:   []string{"x", "a", "b", "c", "y"},
			pattern: []string{"a", "b", "c"},
			expect:  true,
		},
		{
			name:    "no match",
			chain:   []string{"a", "x", "y"},
			pattern: []string{"b", "c"},
			expect:  false,
		},
		{
			name:    "overlapping match",
			chain:   []string{"b", "b", "c"},
			pattern: []string{"b", "c"},
			expect:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsExactPattern(tt.chain, tt.pattern)
			if result != tt.expect {
				t.Errorf("chain=%v, pattern=%v, got=%v, want=%v", tt.chain, tt.pattern, result, tt.expect)
			}
		})
	}
}

func TestContainsSubSequence(t *testing.T) {
	tests := []struct {
		name    string
		chain   []string
		pattern []string
		expect  bool
	}{
		{
			name:    "simple subsequence",
			chain:   []string{"a", "x", "b", "y", "c"},
			pattern: []string{"a", "b", "c"},
			expect:  true,
		},
		{
			name:    "non-subsequence",
			chain:   []string{"a", "x", "y", "b"},
			pattern: []string{"a", "b", "c"},
			expect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSubSequence(tt.chain, tt.pattern)
			if result != tt.expect {
				t.Errorf("chain=%v, pattern=%v, got=%v, want=%v", tt.chain, tt.pattern, result, tt.expect)
			}
		})
	}
}
