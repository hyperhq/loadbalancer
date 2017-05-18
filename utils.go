package main

import (
	"fmt"
	"strings"
)

func parseLabels(labels string) (map[string]string, error) {
	result := make(map[string]string)

	labelPairs := strings.Split(labels, ",")
	for _, label := range labelPairs {
		if len(label) == 0 {
			continue
		}

		pair := strings.Split(label, "=")
		if len(pair) != 2 {
			return nil, fmt.Errorf("Label param %q is illegal", labels)
		}

		result[pair[0]] = pair[1]
	}

	return result, nil
}
