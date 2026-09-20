package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Node        NodeConfig        `json:"node" yaml:"node"`
	Capture     CaptureConfig     `json:"capture" yaml:"capture"`
	Patterns    PatternConfig     `json:"patterns" yaml:"patterns"`
	Intel       IntelConfig       `json:"intel" yaml:"intel"`
	Evidence    EvidenceConfig    `json:"evidence" yaml:"evidence"`
	Event       EventConfig       `json:"event" yaml:"event"`
	Flow        FlowConfig        `json:"flow" yaml:"flow"`
	Aggregation AggregationConfig `json:"aggregation" yaml:"aggregation"`
	Server      ServerConfig      `json:"server" yaml:"server"`
	Storage     StorageConfig     `json:"storage" yaml:"storage"`
	Runtime     RuntimeConfig     `json:"-" yaml:"-"`
}

// Storage settings change representation/lifecycle, never detection or evidence limits.
type StorageConfig struct {
	Backend                string `json:"backend" yaml:"backend"`
	ArchiveDir             string `json:"archive_dir" yaml:"archive_dir"`
	ArchiveAfterHours      int    `json:"archive_after_hours" yaml:"archive_after_hours"`
	MaintenanceIntervalSec int    `json:"maintenance_interval_sec" yaml:"maintenance_interval_sec"`
	ArchiveBatchSize       int    `json:"archive_batch_size" yaml:"archive_batch_size"`
	HighWaterBytes         int64  `json:"high_water_bytes" yaml:"high_water_bytes"`
	LowWaterBytes          int64  `json:"low_water_bytes" yaml:"low_water_bytes"`
	MinFreeBytes           uint64 `json:"min_free_bytes" yaml:"min_free_bytes"`
}

func (s StorageConfig) Validate() error {
	if s.Backend != "" && s.Backend != "v2" && s.Backend != "legacy" {
		return fmt.Errorf("storage.backend must be v2 or legacy")
	}
	if s.ArchiveAfterHours < 0 || s.MaintenanceIntervalSec < 0 || s.ArchiveBatchSize < 0 || s.ArchiveBatchSize > 1000 || s.HighWaterBytes < 0 || s.LowWaterBytes < 0 {
		return fmt.Errorf("invalid storage limit")
	}
	if s.HighWaterBytes > 0 && s.LowWaterBytes >= s.HighWaterBytes {
		return fmt.Errorf("storage.low_water_bytes must be smaller than high_water_bytes")
	}
	return nil
}

type RuntimeConfig struct {
	ConfigOnly bool
}

type NodeConfig struct {
	DeviceID      string `json:"device_id" yaml:"device_id"`
	ManagementURL string `json:"management_url" yaml:"management_url"`
	// APIKey is sent as the X-API-Key header on event push; required by the
	// management internal ingest endpoint only when it sets internal_api_key.
	APIKey string `json:"api_key" yaml:"api_key"`
	// HomeNet lists local network ranges (CIDR) used to classify event
	// direction as inbound/outbound/lateral. Empty leaves direction "unknown".
	HomeNet []string `json:"home_net" yaml:"home_net"`
}

type CaptureConfig struct {
	Interface   string `json:"interface" yaml:"interface"`
	PCAPFile    string `json:"pcap_file" yaml:"pcap_file"`
	BPFFilter   string `json:"bpf_filter" yaml:"bpf_filter"`
	Snaplen     int32  `json:"snaplen" yaml:"snaplen"`
	Promiscuous bool   `json:"promiscuous" yaml:"promiscuous"`
}

type PatternConfig struct {
	// Enable turns on payload fingerprint (regex) detection from PatternDir.
	// Disabled by default so only intel IOC matches generate events; the node
	// then never pushes events from rules outside the intel store.
	Enable     bool   `json:"enable" yaml:"enable"`
	PatternDir string `json:"pattern_dir" yaml:"pattern_dir"`
}

type IntelConfig struct {
	IntelFile               string `json:"intel_file" yaml:"intel_file"`
	ReloadIntervalSec       int    `json:"reload_interval_sec" yaml:"reload_interval_sec"`
	EnableHotReload         bool   `json:"enable_hot_reload" yaml:"enable_hot_reload"`
	PruneExpiredIntervalSec int    `json:"prune_expired_interval_sec" yaml:"prune_expired_interval_sec"`
	AcceptSTIX              bool   `json:"accept_stix" yaml:"accept_stix"`
	DefaultSource           string `json:"default_source" yaml:"default_source"`
	MaxItems                int    `json:"max_items" yaml:"max_items"`
	IocSyncDir              string `json:"ioc_sync_dir" yaml:"ioc_sync_dir"`
	IocSyncDir2             string `json:"ioc_sync_dir2" yaml:"ioc_sync_dir2"`
	EnableIocSync           bool   `json:"enable_ioc_sync" yaml:"enable_ioc_sync"`
	IocSyncIntervalMin      int    `json:"ioc_sync_interval_min" yaml:"ioc_sync_interval_min"`
	IocSyncRetainDays       int    `json:"ioc_sync_retain_days" yaml:"ioc_sync_retain_days"`
}

type EvidenceConfig struct {
	EnablePCAPSave  bool   `json:"enable_pcap_save" yaml:"enable_pcap_save"`
	PCAPDir         string `json:"pcap_dir" yaml:"pcap_dir"`
	RetainDays      int    `json:"retain_days" yaml:"retain_days"`
	HashEvidenceDir bool   `json:"hash_evidence_dir" yaml:"hash_evidence_dir"`
	ArchiveMonthly  bool   `json:"archive_monthly" yaml:"archive_monthly"`
}

type EventConfig struct {
	EnablePush       bool   `json:"enable_push" yaml:"enable_push"`
	QueueDB          string `json:"queue_db" yaml:"queue_db"`
	PushBatchSize    int    `json:"push_batch_size" yaml:"push_batch_size"`
	RetryIntervalSec int    `json:"retry_interval_sec" yaml:"retry_interval_sec"`
	PushTimeoutSec   int    `json:"push_timeout_sec" yaml:"push_timeout_sec"`
	// MaxPushRetry caps how many times a failed event is retried before it is
	// abandoned (kept in the queue for inspection but no longer pushed), so a
	// dead management endpoint cannot make the backlog replay forever.
	// 0 means retry without limit.
	MaxPushRetry int `json:"max_push_retry" yaml:"max_push_retry"`
	// LocalHitWindowSec sets the sliding window (seconds) for the node-local
	// burst counter stamped on events (local_hit_count). 0 disables it.
	LocalHitWindowSec int `json:"local_hit_window_sec" yaml:"local_hit_window_sec"`
}

type FlowConfig struct {
	MaxFlows           int `json:"max_flows" yaml:"max_flows"`
	IdleTimeoutSec     int `json:"idle_timeout_sec" yaml:"idle_timeout_sec"`
	CleanupIntervalSec int `json:"cleanup_interval_sec" yaml:"cleanup_interval_sec"`
}

// AggregationConfig controls bounded bidirectional session and HTTP/1.x
// transaction correlation. Mode "packet" preserves the 1.4 behavior; mode
// "session" enables request/response enrichment revisions.
type AggregationConfig struct {
	Mode                      string `json:"mode" yaml:"mode"`
	EnableTransactionLink     bool   `json:"enable_transaction_link" yaml:"enable_transaction_link"`
	ResponseWaitSec           int    `json:"response_wait_sec" yaml:"response_wait_sec"`
	MaxSessions               int    `json:"max_sessions" yaml:"max_sessions"`
	MaxTransactionsPerSession int    `json:"max_transactions_per_session" yaml:"max_transactions_per_session"`
	MaxPacketsPerTransaction  int    `json:"max_packets_per_transaction" yaml:"max_packets_per_transaction"`
	MaxReassemblyBytesPerSide int    `json:"max_reassembly_bytes_per_side" yaml:"max_reassembly_bytes_per_side"`
	MaxOutOfOrderBytes        int    `json:"max_out_of_order_bytes" yaml:"max_out_of_order_bytes"`
	StorePacketIndex          bool   `json:"store_packet_index" yaml:"store_packet_index"`
	SaveFullSessionPCAP       bool   `json:"save_full_session_pcap" yaml:"save_full_session_pcap"`
}

type ServerConfig struct {
	Enable bool   `json:"enable" yaml:"enable"`
	Listen string `json:"listen" yaml:"listen"`
	Token  string `json:"token" yaml:"token"`
}

func Default() Config {
	return Config{
		Storage: StorageConfig{Backend: "v2", ArchiveAfterHours: 24, MaintenanceIntervalSec: 60, ArchiveBatchSize: 100},
		Node:    NodeConfig{DeviceID: "node-001", ManagementURL: "http://127.0.0.1:8080/api/events"},
		Capture: CaptureConfig{
			Interface:   "eth0",
			Snaplen:     1600,
			Promiscuous: true,
		},
		Patterns: PatternConfig{PatternDir: "./patterns"},
		Intel: IntelConfig{
			IntelFile:               "./configs/intel.yaml",
			ReloadIntervalSec:       30,
			EnableHotReload:         true,
			PruneExpiredIntervalSec: 300,
			AcceptSTIX:              true,
			DefaultSource:           "Threat Intel Hub",
			MaxItems:                100000,
			IocSyncDir:              "/data/yt",
			IocSyncDir2:             "/data/yt/ioc",
			EnableIocSync:           true,
			IocSyncIntervalMin:      60,
			IocSyncRetainDays:       10,
		},
		Evidence: EvidenceConfig{EnablePCAPSave: true, PCAPDir: "./data/evidence", RetainDays: 7, HashEvidenceDir: true, ArchiveMonthly: true},
		Event: EventConfig{
			EnablePush:        true,
			QueueDB:           "./data/event_queue.db",
			PushBatchSize:     100,
			RetryIntervalSec:  30,
			PushTimeoutSec:    5,
			MaxPushRetry:      20,
			LocalHitWindowSec: 60,
		},
		Flow: FlowConfig{
			MaxFlows:           1000000,
			IdleTimeoutSec:     120,
			CleanupIntervalSec: 30,
		},
		Aggregation: AggregationConfig{
			Mode:                      "packet",
			EnableTransactionLink:     false,
			ResponseWaitSec:           30,
			MaxSessions:               100000,
			MaxTransactionsPerSession: 16,
			MaxPacketsPerTransaction:  128,
			MaxReassemblyBytesPerSide: 262144,
			MaxOutOfOrderBytes:        65536,
			StorePacketIndex:          true,
		},
		Server: ServerConfig{Enable: true, Listen: "127.0.0.1:19090"},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	if err := cfg.Storage.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadWithFlags(args []string) (Config, string, []string, error) {
	fs := flag.NewFlagSet("ta_node", flag.ContinueOnError)
	configPath := fs.String("config", "./configs/ta_node.yaml", "config file")
	iface := fs.String("interface", "", "capture interface")
	pcapFile := fs.String("pcap-file", "", "pcap file")
	deviceID := fs.String("device-id", "", "device id")
	managementURL := fs.String("management-url", "", "management event url")
	patternDir := fs.String("pattern-dir", "", "pattern directory")
	intelFile := fs.String("intel-file", "", "intel yaml file")
	eventDB := fs.String("event-db", "", "event sqlite queue db")
	enablePCAPSave := fs.Bool("enable-pcap-save", false, "save evidence pcap")
	configOnly := fs.Bool("config-only", false, "start local config api without opening capture source")
	err := fs.Parse(args)
	if err != nil {
		return Config{}, "", nil, err
	}
	cfg, err := Load(*configPath)
	if err != nil && !os.IsNotExist(err) {
		return Config{}, "", nil, err
	}
	if *iface != "" {
		cfg.Capture.Interface = *iface
	}
	if *pcapFile != "" {
		cfg.Capture.PCAPFile = *pcapFile
	}
	if *deviceID != "" {
		cfg.Node.DeviceID = *deviceID
	}
	if *managementURL != "" {
		cfg.Node.ManagementURL = *managementURL
	}
	if *patternDir != "" {
		cfg.Patterns.PatternDir = *patternDir
	}
	if *intelFile != "" {
		cfg.Intel.IntelFile = *intelFile
	}
	if *eventDB != "" {
		cfg.Event.QueueDB = *eventDB
	}
	if flagWasSet(fs, "enable-pcap-save") {
		cfg.Evidence.EnablePCAPSave = *enablePCAPSave
	}
	cfg.Runtime.ConfigOnly = *configOnly
	return cfg, *configPath, fs.Args(), nil
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func (c Config) ReloadInterval() time.Duration {
	return time.Duration(c.Intel.ReloadIntervalSec) * time.Second
}

func (c Config) PruneExpiredInterval() time.Duration {
	return time.Duration(c.Intel.PruneExpiredIntervalSec) * time.Second
}

func (c Config) IocSyncInterval() time.Duration {
	return time.Duration(c.Intel.IocSyncIntervalMin) * time.Minute
}

func (c Config) RetryInterval() time.Duration {
	return time.Duration(c.Event.RetryIntervalSec) * time.Second
}

func (c Config) PushTimeout() time.Duration {
	return time.Duration(c.Event.PushTimeoutSec) * time.Second
}

func (c Config) FlowIdleTimeout() time.Duration {
	return time.Duration(c.Flow.IdleTimeoutSec) * time.Second
}

func (c Config) FlowCleanupInterval() time.Duration {
	interval := c.Flow.CleanupIntervalSec
	if interval <= 0 {
		interval = 30
	}
	return time.Duration(interval) * time.Second
}

func (c Config) SessionAggregationEnabled() bool {
	return c.Aggregation.Mode == "session" && c.Aggregation.EnableTransactionLink
}
