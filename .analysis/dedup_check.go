package main

import (
	"fmt"

	"ta_node/internal/intel"
)

func main() {
	items, err := intel.LoadFile("../docs/intel-clean.yaml")
	if err != nil {
		fmt.Println("load error:", err)
		return
	}
	fmt.Println("loaded items:", len(items))
	byKey := map[string][]intel.ThreatIntel{}
	for _, it := range items {
		k := intel.CanonicalKey(it)
		byKey[k] = append(byKey[k], it)
	}
	fmt.Println("unique canonical keys (Go):", len(byKey))
	dups := 0
	for k, lst := range byKey {
		if len(lst) > 1 {
			dups++
			fmt.Printf("DUP key=%s count=%d\n", k, len(lst))
			for _, it := range lst {
				fmt.Printf("   id=%s value=%q\n", it.ID, it.Value)
			}
		}
	}
	fmt.Println("dup groups:", dups)
}
