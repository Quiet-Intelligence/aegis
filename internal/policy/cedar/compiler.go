package cedar

import (
	"regexp"
	"strings"
)

// BPFMapFormat represents the output needed for the BPF maps.
type BPFMapFormat struct {
	DeniedHashes []string
	DeniedPaths  []string
}

// CompileToBPF takes a Cedar policy string and compiles it to BPF map structures.
// This is a naive compiler for CE-4 that extracts attributes from simple Cedar forbid rules.
func CompileToBPF(cedarPolicy string) BPFMapFormat {
	var format BPFMapFormat

	// Very simple regex to parse the when { ... } block for our specific migration format
	hashRegex := regexp.MustCompile(`resource\.binary_hash\s*==\s*"([^"]+)"`)
	pathRegex := regexp.MustCompile(`resource\.path_pattern\s*like\s*"([^"]+)\*"`)

	// Split policy by ';' to handle multiple statements
	statements := strings.Split(cedarPolicy, ";")

	for _, stmt := range statements {
		if !strings.Contains(stmt, "forbid(") {
			continue
		}

		if matches := hashRegex.FindStringSubmatch(stmt); len(matches) > 1 {
			format.DeniedHashes = append(format.DeniedHashes, matches[1])
		}

		if matches := pathRegex.FindStringSubmatch(stmt); len(matches) > 1 {
			// Restore the trailing '*' if needed by BPF map, or just store the prefix.
			// Currently storing just the prefix path.
			format.DeniedPaths = append(format.DeniedPaths, matches[1])
		}
	}

	return format
}
