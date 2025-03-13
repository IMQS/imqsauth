package utils

// Helper function to compute the difference of two sets
func ComputeDifference(source, target []string) []string {
	resultSet := []string{}
	targetSet := make(map[string]bool)

	// Populate the target set for quick lookup
	for _, item := range target {
		targetSet[item] = true
	}

	// Find items in source that are not in target
	for _, item := range source {
		if !targetSet[item] {
			resultSet = append(resultSet, item)
		}
	}

	return resultSet
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

// removeStr removes a specific string from a slice
func RemoveStr(slice []string, str string) []string {
	var result []string
	for _, v := range slice {
		if v != str {
			result = append(result, v)
		}
	}
	return result
}
