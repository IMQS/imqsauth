package utils

import (
	"reflect"
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
			result := ComputeDifference(test.source, test.target)
			if !equal(result, test.expected) {
				t.Errorf("For source %v and target %v, expected %v, got %v", test.source, test.target, test.expected, result)
			}
		})
	}
}

func TestRemoveStr(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		str      string
		expected []string
	}{
		{
			name:     "Remove existing element",
			slice:    []string{"apple", "banana", "cherry"},
			str:      "banana",
			expected: []string{"apple", "cherry"},
		},
		{
			name:     "Remove non-existing element",
			slice:    []string{"apple", "banana", "cherry"},
			str:      "orange",
			expected: []string{"apple", "banana", "cherry"},
		},
		{
			name:     "Remove from empty slice",
			slice:    []string{},
			str:      "banana",
			expected: []string{},
		},
		{
			name:     "Remove multiple occurrences",
			slice:    []string{"apple", "banana", "banana", "cherry"},
			str:      "banana",
			expected: []string{"apple", "cherry"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveStr(tt.slice, tt.str)

			// Ensure nil and empty slice are treated the same
			if result == nil {
				result = []string{}
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}
