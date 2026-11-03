package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type ServiceEntry struct {
	Name     string `json:"name"`
	Image    string `json:"image"`
	Category string `json:"category"`
	File     string `json:"file"`
}

type PortEntry struct {
	Service       string `json:"service"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	HostIP        string `json:"host_ip,omitempty"`
	AllInterfaces bool   `json:"all_interfaces"`
	File          string `json:"file"`
}

type VolumeEntry struct {
	Service     string `json:"service"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
	File        string `json:"file"`
}

type NetworkEntry struct {
	Name     string `json:"name"`
	Internal bool   `json:"internal"`
	File     string `json:"file"`
}

type EnvKeyEntry struct {
	Key      string   `json:"key"`
	Services []string `json:"services"`
}

type InventoryReport struct {
	Services []ServiceEntry `json:"services"`
	Ports    []PortEntry    `json:"ports"`
	Volumes  []VolumeEntry  `json:"volumes"`
	Networks []NetworkEntry `json:"networks"`
	EnvKeys  []EnvKeyEntry  `json:"env_keys"`
}

func classifyImage(image string) string {
	lower := strings.ToLower(image)
	if _, ok := collect.IsAgentRuntimeImage(image); ok {
		return "agent-runtime"
	}
	for _, needle := range []string{"ollama", "vllm", "llama.cpp", "llamacpp", "lmstudio", "lm-studio"} {
		if strings.Contains(lower, needle) {
			return "inference"
		}
	}
	for _, needle := range []string{"open-webui", "openwebui", "gradio"} {
		if strings.Contains(lower, needle) {
			return "ui"
		}
	}
	for _, needle := range []string{"qdrant", "chroma", "weaviate", "milvus"} {
		if strings.Contains(lower, needle) {
			return "vector-db"
		}
	}
	for _, needle := range []string{"redis", "valkey", "postgres", "pgvector"} {
		if strings.Contains(lower, needle) {
			return "datastore"
		}
	}
	return "other"
}

func buildInventory(collected *collect.Collected) InventoryReport {
	var inv InventoryReport
	envKeyServices := map[string]map[string]bool{}

	for _, cf := range collected.ComposeFiles {
		rel := cf.Path

		for name, net := range cf.Networks {
			inv.Networks = append(inv.Networks, NetworkEntry{
				Name:     name,
				Internal: net.Internal,
				File:     rel,
			})
		}

		for _, svc := range cf.Services {
			category := classifyImage(svc.Image)
			inv.Services = append(inv.Services, ServiceEntry{
				Name:     svc.Name,
				Image:    svc.Image,
				Category: category,
				File:     rel,
			})

			for _, p := range svc.Ports {
				inv.Ports = append(inv.Ports, PortEntry{
					Service:       svc.Name,
					HostPort:      p.HostPort,
					ContainerPort: p.TargetPort,
					HostIP:        p.HostIP,
					AllInterfaces: p.IsAllInterfaces(),
					File:          rel,
				})
			}

			for _, v := range svc.Volumes {
				src, dst, ro := parseVolumeSpec(v)
				inv.Volumes = append(inv.Volumes, VolumeEntry{
					Service:     svc.Name,
					Source:      src,
					Destination: dst,
					ReadOnly:    ro,
					File:        rel,
				})
			}

			for _, e := range svc.Environment {
				key := e
				if idx := strings.Index(e, "="); idx > 0 {
					key = e[:idx]
				}
				key = strings.TrimSpace(key)
				if key == "" {
					continue
				}
				if envKeyServices[key] == nil {
					envKeyServices[key] = map[string]bool{}
				}
				envKeyServices[key][svc.Name] = true
			}
		}
	}

	keys := make([]string, 0, len(envKeyServices))
	for k := range envKeyServices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		svcs := make([]string, 0, len(envKeyServices[k]))
		for s := range envKeyServices[k] {
			svcs = append(svcs, s)
		}
		sort.Strings(svcs)
		inv.EnvKeys = append(inv.EnvKeys, EnvKeyEntry{Key: k, Services: svcs})
	}

	sort.Slice(inv.Services, func(i, j int) bool { return inv.Services[i].Name < inv.Services[j].Name })
	sort.Slice(inv.Networks, func(i, j int) bool { return inv.Networks[i].Name < inv.Networks[j].Name })

	return inv
}

func buildInventoryFromFiles(files []compose.File) InventoryReport {
	c := &collect.Collected{ComposeFiles: files}
	return buildInventory(c)
}

func parseVolumeSpec(v string) (src, dst string, ro bool) {
	parts := strings.Split(v, ":")
	switch len(parts) {
	case 1:
		return "", parts[0], false
	case 2:
		return parts[0], parts[1], false
	default:
		ro = strings.Contains(strings.ToLower(parts[2]), "ro")
		return parts[0], parts[1], ro
	}
}

func printInventoryText(inv InventoryReport) {
	fmt.Printf("Services (%d):\n", len(inv.Services))
	for _, s := range inv.Services {
		fmt.Printf("  %-20s %-30s [%s]\n", s.Name, s.Image, s.Category)
	}

	if len(inv.Ports) > 0 {
		fmt.Printf("\nPorts (%d):\n", len(inv.Ports))
		for _, p := range inv.Ports {
			iface := "all interfaces"
			if !p.AllInterfaces {
				iface = p.HostIP
				if iface == "" {
					iface = "localhost"
				}
			}
			fmt.Printf("  %-20s %d:%d (%s)\n", p.Service, p.HostPort, p.ContainerPort, iface)
		}
	}

	if len(inv.Volumes) > 0 {
		fmt.Printf("\nVolumes (%d):\n", len(inv.Volumes))
		for _, v := range inv.Volumes {
			roStr := ""
			if v.ReadOnly {
				roStr = " [ro]"
			}
			fmt.Printf("  %-20s %s -> %s%s\n", v.Service, v.Source, v.Destination, roStr)
		}
	}

	if len(inv.Networks) > 0 {
		fmt.Printf("\nNetworks (%d):\n", len(inv.Networks))
		for _, n := range inv.Networks {
			internal := ""
			if n.Internal {
				internal = " (internal)"
			}
			fmt.Printf("  %s%s\n", n.Name, internal)
		}
	}

	if len(inv.EnvKeys) > 0 {
		fmt.Printf("\nEnvironment keys (%d):\n", len(inv.EnvKeys))
		for _, e := range inv.EnvKeys {
			fmt.Printf("  %-30s used by: %s\n", e.Key, strings.Join(e.Services, ", "))
		}
	}
}

func runInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var collected *collect.Collected
	if *recursive {
		dirs := findScanDirs(absPath)
		merged := &collect.Collected{Root: absPath}
		for _, d := range dirs {
			c, err := collect.WalkAndCollect(d)
			if err != nil {
				continue
			}
			merged.ComposeFiles = append(merged.ComposeFiles, c.ComposeFiles...)
		}
		collected = merged
	} else {
		collected, err = collect.WalkAndCollect(absPath)
		if err != nil {
			return err
		}
	}

	if len(collected.ParseErrors) > 0 {
		fmt.Fprintln(os.Stderr, "tasia inventory: cannot parse config; fix parse errors first")
		os.Exit(2)
	}

	inv := buildInventory(collected)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(inv, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		printInventoryText(inv)
	}
	return nil
}
