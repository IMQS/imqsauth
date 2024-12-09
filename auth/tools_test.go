package imqsauth

import (
	"testing"
)

// Test the computeDifference function
func TestComputeDifference(t *testing.T) {
	tests := []struct {
		source   []string
		target   []string
		expected []string
	}{
		{
			source:   []string{"a", "b", "c"},
			target:   []string{"b", "c", "d"},
			expected: []string{"a"},
		},
		{
			source:   []string{"apple", "banana", "cherry"},
			target:   []string{"banana", "cherry", "date"},
			expected: []string{"apple"},
		},
		{
			source:   []string{"x", "y", "z"},
			target:   []string{"a", "b", "c"},
			expected: []string{"x", "y", "z"}, // All source items are unique
		},
		{
			source:   []string{"a", "b", "c"},
			target:   []string{"a", "b", "c"},
			expected: []string{}, // No difference
		},
		{
			source:   []string{},
			target:   []string{"x", "y", "z"},
			expected: []string{}, // Empty source
		},
		{
			source:   []string{"a", "b", "c"},
			target:   []string{},
			expected: []string{"a", "b", "c"}, // Empty target
		},
	}

	// Iterate over each test case
	for _, test := range tests {
		t.Run("Testing computeDifference", func(t *testing.T) {
			result := computeDifference(test.source, test.target)
			if !equal(result, test.expected) {
				t.Errorf("For source %v and target %v, expected %v, got %v", test.source, test.target, test.expected, result)
			}
		})
	}
}

// Helper function to compare two slices of strings
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
