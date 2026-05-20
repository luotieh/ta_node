package config

import (
	"flag"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Node     NodeConfig     `yaml:"node"`
	Capture  CaptureConfig  `yaml:"capture"`
	Patterns PatternConfig  `yaml:"patterns"`
	Intel    IntelConfig    `yaml:"intel"`
	Evidence EvidenceConfig `yaml:"evidence"`
	Event    EventConfig    `yaml:"event"`
	Server   ServerConfig   `yaml:"server"`
}

type NodeConfig struct {
	DeviceID      string `yaml:"device_id"`
	ManagementURL string `yaml:"management_url"`
	Token         string `yaml:"token"`
}

type CaptureConfig struct {
	Interface   string `yaml:"interface"`
	PCAPFile    string `yaml:"pcap_file"`
	BPFFilter   string `yaml:"bpf_filter"`
	Snaplen     int32  `yaml:"snaplen"`
	Promiscuous bool   `yaml:"promiscuous"`
}

type PatternConfig struct {
	PatternDir string `yaml:"pattern_dir"`
}

type IntelConfig struct {
	IntelFile         string `yaml:"intel_file"`
	ReloadIntervalSec int    `yaml:"reload_interval_sec"`
	EnableHotReload   bool   `yaml:"enable_hot_reload"`
}

type EvidenceConfig struct {
	EnablePCAPSave bool   `yaml:"enable_pcap_save"`
	PCAPDir        string `yaml:"pcap_dir"`
}

type EventConfig struct {
	QueueDB          string `yaml:"queue_db"`
	PushBatchSize    int    `yaml:"push_batch_size"`
	RetryIntervalSec int    `yaml:"retry_interval_sec"`
	PushTimeoutSec   int    `yaml:"push_timeout_sec"`
}

type ServerConfig struct {
	Enable bool   `yaml:"enable"`
	Listen string `yaml:"listen"`
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
			IntelFile:         "./configs/intel.yaml",
			ReloadIntervalSec: 30,
			EnableHotReload:   true,
		},
		Evidence: EvidenceConfig{EnablePCAPSave: true, PCAPDir: "./data/evidence"},
		Event: EventConfig{
			QueueDB:          "./data/event_queue.db",
			PushBatchSize:    100,
			RetryIntervalSec: 30,
			PushTimeoutSec:   5,
		},
		Server: ServerConfig{Enable: true, Listen: "0.0.0.0:19090"},
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

func (c Config) RetryInterval() time.Duration {
	return time.Duration(c.Event.RetryIntervalSec) * time.Second
}

func (c Config) PushTimeout() time.Duration {
	return time.Duration(c.Event.PushTimeoutSec) * time.Second
}
