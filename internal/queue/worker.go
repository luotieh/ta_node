package queue

import (
	"context"
	"log"
	"os"
	"time"
)

type MaintenanceOptions struct {
	ArchiveDir          string
	After, Interval     time.Duration
	Batch               int
	HighWater, LowWater int64
	MinFree             uint64
}

// Maintain never drops data. Capacity alerts require operational action when
// pending traffic or an unavailable archive prevents safe reclamation.
func Maintain(ctx context.Context, q *SQLiteQueue, o MaintenanceOptions) {
	if o.Interval <= 0 {
		o.Interval = time.Minute
	}
	if o.Batch <= 0 {
		o.Batch = 100
	}
	if err := q.RecoverArchives(); err != nil {
		log.Printf("archive recovery: %v", err)
	}
	ticker := time.NewTicker(o.Interval)
	defer ticker.Stop()
	pressure := false
	for {
		stats, err := q.Stats()
		if err != nil {
			log.Printf("queue storage metrics: %v", err)
		} else {
			used := stats.PageBytes - stats.ReusableBytes
			if o.HighWater > 0 && used >= o.HighWater {
				pressure = true
			}
			if pressure && used <= o.LowWater {
				pressure = false
			}
			if pressure || (o.MinFree > 0 && stats.AvailableBytes < o.MinFree) {
				log.Printf("queue storage capacity alert: used=%d file=%d available=%d; no events discarded", used, stats.FileBytes, stats.AvailableBytes)
			}
		}
		if o.ArchiveDir != "" && ctx.Err() == nil {
			// Check destination space too. Never reclaim a source until the destination
			// copy has committed and passed verification.
			if err := os.MkdirAll(o.ArchiveDir, 0750); err != nil {
				log.Printf("archive directory: %v", err)
			} else if free, e := availableBytes(o.ArchiveDir); e != nil {
				log.Printf("archive disk metrics: %v", e)
			} else if o.MinFree > 0 && free < o.MinFree {
				log.Printf("archive capacity alert: available=%d; source preserved", free)
			} else {
				cutoff := time.Now().Add(-o.After)
				if pressure {
					cutoff = time.Now()
				} // only acknowledged history is eligible
				n, e := q.Archive(ctx, o.ArchiveDir, cutoff, o.Batch)
				if e != nil {
					log.Printf("queue archive failed: %v", e)
				} else if n > 0 {
					log.Printf("queue archived %d acknowledged records", n)
				}
			}
			if _, err := q.Collect(10000); err != nil {
				log.Printf("queue content collection: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
