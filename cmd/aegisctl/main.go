package main

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3" // needed for aegisctl standalone
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: aegisctl policy [list|revoke]")
		return
	}

	db, err := sql.Open("sqlite3", "aegis.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	if os.Args[1] == "policy" {
		if len(os.Args) < 3 {
			return
		}
		cmd := os.Args[2]
		
		if cmd == "list" {
			rows, _ := db.Query("SELECT id, match_type, match_value, expires_at FROM policy_entries WHERE revoked_at IS NULL")
			defer rows.Close()
			fmt.Println("ID\tTYPE\tVALUE\tEXPIRES")
			for rows.Next() {
				var id int
				var mType, mVal string
				var expires time.Time
				rows.Scan(&id, &mType, &mVal, &expires)
				fmt.Printf("%d\t%s\t%s\t%s\n", id, mType, mVal, expires.Format(time.RFC3339))
			}
		} else if cmd == "revoke" {
			if len(os.Args) < 4 {
				fmt.Println("Missing policy ID")
				return
			}
			id := os.Args[3]
			db.Exec("UPDATE policy_entries SET revoked_at = ? WHERE id = ?", time.Now(), id)
			fmt.Printf("Revoked policy %s\n", id)
		}
	}
}
