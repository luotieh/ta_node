package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ta_node/internal/capture"
	"ta_node/internal/config"
	"ta_node/internal/detector"
	"ta_node/internal/evidence"
	"ta_node/internal/fingerprint"
	"ta_node/internal/flow"
	"ta_node/internal/intel"
	"ta_node/internal/parser"
	"ta_node/internal/push"
	"ta_node/internal/queue"
	"ta_node/internal/server"
)

func main() {
	cfg, _, rest, err := config.LoadWithFlags(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if len(rest) > 0 && rest[0] == "intel" {
		if err := runIntelCLI(cfg, rest[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := runNode(cfg); err != nil {
		log.Fatal(err)
	}
}

func runNode(cfg config.Config) error {
	rules, err := fingerprint.LoadDir(cfg.Patterns.PatternDir)
	if err != nil {
		return fmt.Errorf("load patterns: %w", err)
	}
	fpEngine := fingerprint.New(rules)
	intelStore, err := intel.NewStore(cfg.Intel.IntelFile)
	if err != nil {
		return fmt.Errorf("load intel: %w", err)
	}
	intelMatcher := intel.NewMatcher(intelStore)
	q, err := queue.NewSQLite(cfg.Event.QueueDB)
	if err != nil {
		return fmt.Errorf("open event queue: %w", err)
	}
	defer q.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := push.NewClient(cfg.Node.ManagementURL, cfg.Node.Token, cfg.PushTimeout())
	go push.StartWorker(ctx, q, client, cfg.Event.PushBatchSize, cfg.RetryInterval())
	if cfg.Server.Enable {
		go func() {
			if err := server.New(intelStore).ListenAndServe(cfg.Server.Listen); err != nil {
				log.Printf("intel api stopped: %v", err)
			}
		}()
	}
	if cfg.Intel.EnableHotReload {
		go hotReload(ctx, intelStore, cfg.ReloadInterval())
	}

	src, err := openSource(cfg)
	if err != nil {
		return err
	}
	defer src.Close()

	agg := flow.NewAggregator()
	det := detector.New(cfg.Node.DeviceID)
	evWriter := evidence.New(cfg.Evidence.EnablePCAPSave, cfg.Evidence.PCAPDir, cfg.Node.DeviceID)

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-src.Packets():
			if !ok {
				return nil
			}
			pf, err := parser.Parse(pkt)
			if err != nil {
				continue
			}
			fpHits := fpEngine.Match(pf)
			intelHits := intelMatcher.MatchPacket(pf)
			if len(fpHits) == 0 && len(intelHits) == 0 {
				agg.Update(pf, nil, nil)
				continue
			}
			f := agg.Update(pf, fpHits, intelHits)
			f.FingerprintHits = fpHits
			f.IntelHits = intelHits
			events := det.Detect(f)
			for _, ev := range events {
				path, err := evWriter.Save(ev.EventID, pkt)
				if err != nil {
					log.Printf("save evidence failed: %v", err)
				}
				if path != "" {
					ev.EvidenceFile = path
				}
				if err := q.Enqueue(ev); err != nil {
					log.Printf("enqueue event failed: %v", err)
				}
			}
		}
	}
}

func openSource(cfg config.Config) (capture.Source, error) {
	if cfg.Capture.PCAPFile != "" {
		return capture.NewPCAPReader(cfg.Capture.PCAPFile, cfg.Capture.BPFFilter)
	}
	return capture.NewInterfaceCapture(cfg.Capture.Interface, cfg.Capture.Snaplen, cfg.Capture.Promiscuous, cfg.Capture.BPFFilter)
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
