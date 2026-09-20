// ta_queue operates only on explicitly selected offline databases. It does not
// stop services, overwrite source files, or remove old databases automatically.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"ta_node/internal/queue"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	fs := flag.NewFlagSet("ta_queue", flag.ContinueOnError)
	source := fs.String("source", "", "frozen, checkpointed source database")
	destination := fs.String("destination", "", "separate destination; resumes same frozen source")
	backend := fs.String("backend", "v2", "destination format: v2 or legacy (rollback export)")
	inspect := fs.Bool("inspect", false, "read-only storage statistics and recent event summaries")
	offline := fs.Bool("offline", false, "confirm source AND destination are not used by a running node")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *inspect {
		if *source == "" {
			return fmt.Errorf("--source required")
		}
		stats, err := queue.InspectStorage(*source)
		if err != nil {
			return err
		}
		logs, err := queue.RecentPushSummaries(*source, 50)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"storage": stats, "items": logs})
	}
	if !*offline || *source == "" || *destination == "" {
		return fmt.Errorf("usage: ta_queue --offline --source SOURCE --destination DEST [--backend v2|legacy]")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	n, err := queue.MigrateFrozen(ctx, *source, *destination, *backend)
	if err != nil {
		return fmt.Errorf("migration paused after %d committed rows: %w", n, err)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"copied_rows": n, "destination": *destination, "verified": true})
}
