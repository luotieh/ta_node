package config

import (
	"flag"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Node     NodeConfig     `json:"node" yaml:"node"`
	Capture  CaptureConfig  `json:"capture" yaml:"capture"`
	Patterns PatternConfig  `json:"patterns" yaml:"patterns"`
	Intel    IntelConfig    `json:"intel" yaml:"intel"`
	Evidence EvidenceConfig `json:"evidence" yaml:"evidence"`
	Event    EventConfig    `json:"event" yaml:"event"`
	Flow     FlowConfig     `json:"flow" yaml:"flow"`
	Server   ServerConfig   `json:"server" yaml:"server"`
	Runtime  RuntimeConfig  `json:"-" yaml:"-"`
}

type RuntimeConfig struct {
	ConfigOnly bool
}

type NodeConfig struct {
	DeviceID      string `json:"device_id" yaml:"device_id"`
	ManagementURL string `json:"management_url" yaml:"management_url"`
	Token         string `json:"token" yaml:"token"`
	// APIKey is sent as the X-API-Key header on event push; required by the
	// management internal ingest endpoint only when it sets internal_api_key.
	APIKey string `json:"api_key" yaml:"api_key"`
}

type CaptureConfig struct {
	Interface   string `json:"interface" yaml:"interface"`
	PCAPFile    string `json:"pcap_file" yaml:"pcap_file"`
	BPFFilter   string `json:"bpf_filter" yaml:"bpf_filter"`
	Snaplen     int32  `json:"snaplen" yaml:"snaplen"`
	Promiscuous bool   `json:"promiscuous" yaml:"promiscuous"`
}

type PatternConfig struct {
	PatternDir string `json:"pattern_dir" yaml:"pattern_dir"`
}

type IntelConfig struct {
	IntelFile               string `json:"intel_file" yaml:"intel_file"`
	IntelDir                string `json:"intel_dir" yaml:"intel_dir"`
	ReloadIntervalSec       int    `json:"reload_interval_sec" yaml:"reload_interval_sec"`
	EnableHotReload         bool   `json:"enable_hot_reload" yaml:"enable_hot_reload"`
	PruneExpiredIntervalSec int    `json:"prune_expired_interval_sec" yaml:"prune_expired_interval_sec"`
	AcceptSTIX              bool   `json:"accept_stix" yaml:"accept_stix"`
	DefaultSource           string `json:"default_source" yaml:"default_source"`
	MaxItems                int    `json:"max_items" yaml:"max_items"`
}

type EvidenceConfig struct {
	EnablePCAPSave bool   `json:"enable_pcap_save" yaml:"enable_pcap_save"`
	PCAPDir        string `json:"pcap_dir" yaml:"pcap_dir"`
}

type EventConfig struct {
	EnablePush       bool   `json:"enable_push" yaml:"enable_push"`
	QueueDB          string `json:"queue_db" yaml:"queue_db"`
	PushBatchSize    int    `json:"push_batch_size" yaml:"push_batch_size"`
	RetryIntervalSec int    `json:"retry_interval_sec" yaml:"retry_interval_sec"`
	PushTimeoutSec   int    `json:"push_timeout_sec" yaml:"push_timeout_sec"`
}

type FlowConfig struct {
	MaxFlows           int `json:"max_flows" yaml:"max_flows"`
	IdleTimeoutSec     int `json:"idle_timeout_sec" yaml:"idle_timeout_sec"`
	CleanupIntervalSec int `json:"cleanup_interval_sec" yaml:"cleanup_interval_sec"`
}

type ServerConfig struct {
	Enable bool   `json:"enable" yaml:"enable"`
	Listen string `json:"listen" yaml:"listen"`
	Token  string `json:"token" yaml:"token"`
}

func Default() Config {
	return Config{
		Node: NodeConfig{DeviceID: "node-001", ManagementURL: "http://127.0.0.1:8080/api/events"},
		Capture: CaptureConfig{
			Interface:   "eth0",
			Snaplen:     1600,
			Promiscuous: true,
		},
		Patterns: PatternConfig{PatternDir: "./patterns"},
		Intel: IntelConfig{
			IntelFile:               "./configs/intel.yaml",
			IntelDir:                "./configs/intel.d",
			ReloadIntervalSec:       30,
			EnableHotReload:         true,
			PruneExpiredIntervalSec: 300,
			AcceptSTIX:              true,
			DefaultSource:           "Threat Intel Hub",
			MaxItems:                100000,
		},
		Evidence: EvidenceConfig{EnablePCAPSave: true, PCAPDir: "./data/evidence"},
		Event: EventConfig{
			EnablePush:       true,
			QueueDB:          "./data/event_queue.db",
			PushBatchSize:    100,
			RetryIntervalSec: 30,
			PushTimeoutSec:   5,
		},
		Flow: FlowConfig{
			MaxFlows:           1000000,
			IdleTimeoutSec:     120,
			CleanupIntervalSec: 30,
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
	intelDir := fs.String("intel-dir", "", "intel overlay directory (*.yaml/*.yml)")
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
	if *intelDir != "" {
		cfg.Intel.IntelDir = *intelDir
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
