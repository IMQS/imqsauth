package imqsauth

import (
	"reflect"
	"testing"
)

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
			result := removeStr(tt.slice, tt.str)

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
