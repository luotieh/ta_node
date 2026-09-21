package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ta_node/internal/buildinfo"
	"ta_node/internal/capture"
	"ta_node/internal/config"
	"ta_node/internal/correlation"
	"ta_node/internal/counter"
	"ta_node/internal/detector"
	"ta_node/internal/event"
	"ta_node/internal/evidence"
	"ta_node/internal/fingerprint"
	"ta_node/internal/flow"
	"ta_node/internal/intel"
	"ta_node/internal/iocsync"
	"ta_node/internal/parser"
	"ta_node/internal/push"
	"ta_node/internal/queue"
	"ta_node/internal/server"
)

func main() {
	cfg, configPath, rest, err := config.LoadWithFlags(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if len(rest) > 0 && rest[0] == "intel" {
		if err := runIntelCLI(cfg, rest[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := runNode(cfg, configPath); err != nil {
		log.Fatal(err)
	}
}

func runNode(cfg config.Config, configPath string) error {
	log.Printf("ta_node version %s (built %s)", buildinfo.Short(), buildinfo.Get().Time)
	var rules []fingerprint.PatternRule
	if cfg.Patterns.Enable {
		var err error
		rules, err = fingerprint.LoadDir(cfg.Patterns.PatternDir)
		if err != nil {
			return fmt.Errorf("load patterns: %w", err)
		}
		log.Printf("loaded %d fingerprint rules (dir=%q)", len(rules), cfg.Patterns.PatternDir)
	} else {
		log.Printf("fingerprint rules disabled (patterns.enable=false); events come from intel matches only")
	}
	fpEngine := fingerprint.New(rules)
	intelStore, err := intel.NewStore(cfg.Intel.IntelFile)
	if err != nil {
		return fmt.Errorf("load intel: %w", err)
	}
	log.Printf("loaded %d IOCs (file=%q)", intelStore.Stats().Total, cfg.Intel.IntelFile)
	intelMatcher := intel.NewMatcher(intelStore)
	if err := cfg.Storage.Validate(); err != nil {
		return err
	}
	q, err := queue.Open(cfg.Event.QueueDB, cfg.Storage.Backend, cfg.Storage.Shards)
	if err != nil {
		return fmt.Errorf("open event queue: %w", err)
	}
	defer q.Close()
	if err = q.Activate(); err != nil {
		return err
	}
	q.SetMaxRetry(cfg.Event.MaxPushRetry)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		queue.Maintain(ctx, q, queue.MaintenanceOptions{ArchiveDir: cfg.Storage.ArchiveDir, After: time.Duration(cfg.Storage.ArchiveAfterHours) * time.Hour, Interval: time.Duration(cfg.Storage.MaintenanceIntervalSec) * time.Second, Batch: cfg.Storage.ArchiveBatchSize, HighWater: cfg.Storage.HighWaterBytes, LowWater: cfg.Storage.LowWaterBytes, MinFree: cfg.Storage.MinFreeBytes})
	}()
	defer func() { stop(); <-maintenanceDone }()
	log.Printf("queue storage backend=%s archive=%q shards=%d", cfg.Storage.Backend, cfg.Storage.ArchiveDir, max(1, cfg.Storage.Shards))

	client := push.NewClient(cfg.Node.ManagementURL, cfg.Node.APIKey, cfg.PushTimeout())
	if cfg.Event.EnablePush {
		go push.StartWorker(ctx, q, client, cfg.Event.PushBatchSize, cfg.RetryInterval())
	}
	if cfg.Intel.EnableIocSync && cfg.Intel.IocSyncDir != "" {
		dirs := collectSyncDirs(cfg.Intel.IocSyncDir, cfg.Intel.IocSyncDir2)
		syncer := iocsync.New(intelStore, dirs, cfg.Intel.IocSyncRetainDays, cfg.Intel.MaxItems)
		go runIOCSync(ctx, syncer, cfg.IocSyncInterval())
		if cfg.Server.Enable {
			srv := server.New(intelStore, cfg, configPath)
			srv.SetIOCSyncer(syncer)
			srv.SetStorageStats(q.Stats)
			go func() {
				if err := srv.ListenAndServe(cfg.Server.Listen); err != nil {
					log.Printf("intel api stopped: %v", err)
				}
			}()
		}
	} else if cfg.Server.Enable {
		go func() {
			srv := server.New(intelStore, cfg, configPath)
			srv.SetStorageStats(q.Stats)
			if err := srv.ListenAndServe(cfg.Server.Listen); err != nil {
				log.Printf("intel api stopped: %v", err)
			}
		}()
	}
	if cfg.Intel.EnableHotReload {
		go hotReload(ctx, intelStore, cfg.ReloadInterval())
	}
	if cfg.Intel.PruneExpiredIntervalSec > 0 {
		go pruneExpired(ctx, intelStore, cfg.PruneExpiredInterval())
	}
	if cfg.Runtime.ConfigOnly {
		<-ctx.Done()
		return nil
	}

	src, err := openSource(cfg)
	if err != nil {
		return err
	}
	defer src.Close()

	agg := flow.NewAggregator(cfg.Flow.MaxFlows, cfg.FlowIdleTimeout())
	var sessionTracker *correlation.Tracker
	if cfg.SessionAggregationEnabled() {
		sessionTracker = correlation.New(correlation.Options{
			MaxSessions:               cfg.Aggregation.MaxSessions,
			MaxTransactionsPerSession: cfg.Aggregation.MaxTransactionsPerSession,
			MaxPacketsPerTransaction:  cfg.Aggregation.MaxPacketsPerTransaction,
			MaxReassemblyBytesPerSide: cfg.Aggregation.MaxReassemblyBytesPerSide,
			MaxOutOfOrderBytes:        cfg.Aggregation.MaxOutOfOrderBytes,
			ResponseWait:              time.Duration(cfg.Aggregation.ResponseWaitSec) * time.Second,
			RevisionInterval:          time.Duration(cfg.Aggregation.RevisionIntervalSec) * time.Second,
			SessionIdleTimeout:        cfg.FlowIdleTimeout(),
			StorePacketIndex:          cfg.Aggregation.StorePacketIndex,
		})
		log.Printf("bidirectional session aggregation enabled (max_sessions=%d response_wait=%ds)", cfg.Aggregation.MaxSessions, cfg.Aggregation.ResponseWaitSec)
	}
	go flowCleanup(ctx, agg, cfg.FlowCleanupInterval())
	var localHits *counter.Window
	if cfg.Event.LocalHitWindowSec > 0 {
		localHits = counter.New(time.Duration(cfg.Event.LocalHitWindowSec)*time.Second, 0)
	}
	det := detector.New(cfg.Node.DeviceID).
		WithHomeNet(parseHomeNet(cfg.Node.HomeNet)).
		WithSensorVersion(buildinfo.Short()).
		WithLocalCounter(localHits, cfg.Event.LocalHitWindowSec).
		WithEvidenceDir(cfg.Evidence.PCAPDir)
	evWriter := evidence.New(cfg.Evidence.EnablePCAPSave, cfg.Evidence.PCAPDir, cfg.Node.DeviceID,
		cfg.Evidence.HashEvidenceDir, cfg.Evidence.RetainDays, cfg.Evidence.ArchiveMonthly)

	if cfg.Evidence.RetainDays > 0 {
		go evidenceCleanup(ctx, evWriter)
	}
	if cfg.Evidence.ArchiveMonthly {
		go evidenceArchive(ctx, evWriter)
	}

	for {
		select {
		case <-ctx.Done():
			if sessionTracker != nil {
				enqueueContextUpdates(q, sessionTracker.Flush())
			}
			return nil
		case pkt, ok := <-src.Packets():
			if !ok {
				if sessionTracker != nil {
					enqueueContextUpdates(q, sessionTracker.Flush())
				}
				return nil
			}
			pf, err := parser.Parse(pkt)
			if err != nil {
				continue
			}
			fpHits := fpEngine.Match(pf)
			intelHits := intelMatcher.MatchPacket(pf)
			f := agg.Update(pf, fpHits, intelHits)
			var observation correlation.Observation
			if sessionTracker != nil {
				observation = sessionTracker.Observe(pf, f.PacketSequence)
				enqueueContextUpdates(q, observation.Updates)
			}
			if len(fpHits) == 0 && len(intelHits) == 0 {
				continue
			}
			events := det.Detect(f)
			for _, ev := range events {
				path, err := evWriter.Save(ev.EventID, pkt)
				if err != nil {
					log.Printf("save evidence failed: %v", err)
				}
				if path != "" {
					ev.EvidenceFile = path
				}
				if sessionTracker != nil {
					ev = sessionTracker.Register(observation, ev)
				}
				if err := q.Enqueue(ev); err != nil {
					log.Printf("enqueue event failed: %v", err)
				}
			}
		}
	}
}

func enqueueContextUpdates(q queue.EventQueue, updates []event.ThreatEvent) {
	for _, ev := range updates {
		if err := q.Enqueue(ev); err != nil {
			log.Printf("enqueue event context revision failed: %v", err)
		}
	}
}

// collectSyncDirs builds a deduped, non-empty directory list from the primary
// and secondary IOC sync directories configured by the user.
func collectSyncDirs(dirs ...string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, d := range dirs {
		d = strings.TrimSpace(d)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// parseHomeNet converts CIDR strings from config into parsed networks, skipping
// (and logging) any malformed entries so a bad config line cannot stop the node.
func parseHomeNet(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			log.Printf("ignoring invalid home_net entry %q: %v", c, err)
			continue
		}
		nets = append(nets, n)
	}
	return nets
}

func openSource(cfg config.Config) (capture.Source, error) {
	if cfg.Capture.PCAPFile != "" {
		return capture.NewPCAPReader(cfg.Capture.PCAPFile, cfg.Capture.BPFFilter)
	}
	return capture.NewInterfaceCapture(cfg.Capture.Interface, cfg.Capture.Snaplen, cfg.Capture.Promiscuous, cfg.Capture.BPFFilter)
}

// runIOCSync syncs new IOC zips once at startup, then every interval. SyncOnce
// logs its own summary. A non-positive interval falls back to 60m so a
// misconfiguration never panics time.NewTicker.
func runIOCSync(ctx context.Context, s *iocsync.Syncer, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Minute
	}
	syncOnce := func() {
		if _, err := s.SyncOnce(); err != nil {
			log.Printf("iocsync failed: %v", err)
		}
	}
	syncOnce() // run once at startup
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce()
		}
	}
}

func hotReload(ctx context.Context, store *intel.Store, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := store.Reload(); err != nil {
				log.Printf("intel reload failed: %v", err)
			}
		}
	}
}

func flowCleanup(ctx context.Context, agg *flow.Aggregator, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			agg.Cleanup()
		}
	}
}

func pruneExpired(ctx context.Context, store *intel.Store, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if deleted := store.PruneExpired(time.Now().Unix()); deleted > 0 {
				log.Printf("pruned expired intel items: %d", deleted)
			}
		}
	}
}

func evidenceCleanup(ctx context.Context, w *evidence.Writer) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	// run once at startup
	w.CleanupExpired(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.CleanupExpired(time.Now())
		}
	}
}

func evidenceArchive(ctx context.Context, w *evidence.Writer) {
	// Run at startup (within first 5 min), then daily.
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
	}
	w.ArchiveLastMonth(time.Now())
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.ArchiveLastMonth(time.Now())
		}
	}
}

func runIntelCLI(cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ta_node intel add|list|delete|reload")
	}
	store, err := intel.NewStore(cfg.Intel.IntelFile)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"items": store.List()})
	case "reload":
		return store.Reload()
	case "delete":
		id := flagValue(args[1:], "--id")
		if id == "" {
			return fmt.Errorf("--id required")
		}
		return store.Delete(id)
	case "add":
		it := intel.ThreatIntel{
			Type:        flagValue(args[1:], "--type"),
			Value:       flagValue(args[1:], "--value"),
			Category:    flagValue(args[1:], "--category"),
			Severity:    flagValue(args[1:], "--severity"),
			Description: flagValue(args[1:], "--description"),
			Source:      "cli",
			Enabled:     true,
		}
		if it.Type == "" || it.Value == "" {
			return fmt.Errorf("--type and --value required")
		}
		saved, err := store.Add(it)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"success": true, "id": saved.ID})
	default:
		return fmt.Errorf("unknown intel command %q", args[0])
	}
}

func flagValue(args []string, name string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
