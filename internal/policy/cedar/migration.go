package cedar

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// MigratePolicies converts existing policy_entries from SQLite to Cedar statements.
func MigratePolicies(db *sql.DB) (string, error) {
	rows, err := db.Query("SELECT id, repo_id, match_type, match_value FROM policy_entries WHERE revoked_at IS NULL")
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var policies []string

	for rows.Next() {
		var id, repoID int
		var matchType, matchValue string
		if err := rows.Scan(&id, &repoID, &matchType, &matchValue); err != nil {
			continue
		}

		// Example Cedar policy for a deny rule:
		// forbid(
		//     principal == Aegis::Repo::"repoID",
		//     action == Aegis::Action::"Access",
		//     resource
		// ) when { resource.binary_hash == "value" };
		
		attrCondition := ""
		if matchType == "hash" {
			attrCondition = fmt.Sprintf(`resource.binary_hash == "%s"`, matchValue)
		} else if matchType == "path" {
			attrCondition = fmt.Sprintf(`resource.path_pattern like "%s*"`, matchValue)
		}

		policy := fmt.Sprintf(`
@id("policy_entry_%d")
forbid(
    principal == Aegis::Repo::"%d",
    action == Aegis::Action::"Access",
    resource
) when { %s };`, id, repoID, attrCondition)

		policies = append(policies, policy)
	}

	return strings.Join(policies, "\n"), nil
}
