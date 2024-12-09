package imqsauth

// Helper function to compute the difference of two sets
func computeDifference(source, target []string) []string {
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
