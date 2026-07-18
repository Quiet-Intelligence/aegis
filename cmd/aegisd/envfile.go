package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// loadEnvFile populates process env vars from the first config file found.
// It exists because aegisd must run as root (eBPF/LSM attach) and sudo's
// env_reset policy strips user exports like AEGIS_LLM_KEY.
//
// Search order:
//  1. $AEGIS_ENV_FILE (explicit path; used even if other files exist)
//  2. ./aegis.env
//  3. ./.env
//  4. /etc/aegis/aegis.env
//
// Variables already present in the process environment always win — the file
// only fills in what is missing.
func loadEnvFile() {
	var candidates []string
	if explicit := os.Getenv("AEGIS_ENV_FILE"); explicit != "" {
		candidates = []string{explicit}
	} else {
		candidates = []string{"aegis.env", ".env", "/etc/aegis/aegis.env"}
	}

	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		n := applyEnvFile(f)
		f.Close()
		fmt.Printf("Loaded %d config value(s) from %s\n", n, path)
		return
	}
}

// applyEnvFile parses KEY=VALUE lines (supports comments, blank lines,
// optional "export" prefix, single/double quoted values) and sets any var
// that is not already defined in the process environment.
func applyEnvFile(f *os.File) int {
	loaded := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)

		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue // process env wins
		}
		if err := os.Setenv(key, value); err == nil {
			loaded++
		}
	}
	return loaded
}
