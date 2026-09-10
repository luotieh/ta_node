package main

import (
	"fmt"
	"os"

	"ta_node/internal/intel"
)

func main() {
	for _, path := range []string{"../docs/intel-clean.yaml", "../docs/intel-monitor.yaml", "../docs/intel-removed.yaml"} {
		items, err := intel.LoadFile(path)
		if err != nil {
			fmt.Printf("%s: LOAD ERROR: %v\n", path, err)
			os.Exit(1)
		}
		enabled := 0
		types := map[string]int{}
		for _, it := range items {
			if it.Enabled { enabled++ }
			types[it.Type]++
			if it.ExpireAt == 0 { fmt.Printf("%s: item %s missing expire_at\n", path, it.ID) }
		}
		fmt.Printf("%s: loaded %d items (enabled=%d) types=%v\n", path, len(items), enabled, types)
	}
	fmt.Println("GO LOADER VALIDATION OK")
}
