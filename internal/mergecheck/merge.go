package mergecheck

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type MergedService struct {
	Name        string            `json:"name"`
	Image       string            `json:"image,omitempty"`
	Ports       []compose.PortMapping `json:"ports,omitempty"`
	Volumes     []string          `json:"volumes,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Sources     []string          `json:"sources"`
	Overrides   []Override        `json:"overrides,omitempty"`
}

type Override struct {
	Field    string `json:"field"`
	FileA    string `json:"file_a"`
	FileB    string `json:"file_b"`
	ValueA   string `json:"value_a"`
	ValueB   string `json:"value_b"`
}

type MergeResult struct {
	Path     string           `json:"path"`
	Services []MergedService  `json:"services"`
	Warnings []string         `json:"warnings,omitempty"`
}

func SimulateMerge(collected *collect.Collected) MergeResult {
	type svcEntry struct {
		svc  compose.Service
		file string
	}

	byName := map[string][]svcEntry{}
	var order []string

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			if _, exists := byName[svc.Name]; !exists {
				order = append(order, svc.Name)
			}
			byName[svc.Name] = append(byName[svc.Name], svcEntry{svc: svc, file: cf.Path})
		}
	}

	var services []MergedService
	var warnings []string

	for _, name := range order {
		entries := byName[name]
		merged := MergedService{
			Name:        name,
			Environment: map[string]string{},
		}

		var sources []string
		for _, e := range entries {
			sources = append(sources, e.file)

			if e.svc.Image != "" {
				if merged.Image != "" && merged.Image != e.svc.Image {
					merged.Overrides = append(merged.Overrides, Override{
						Field:  "image",
						FileA:  sources[0],
						FileB:  e.file,
						ValueA: merged.Image,
						ValueB: e.svc.Image,
					})
					warnings = append(warnings, fmt.Sprintf("service %q: image overridden from %q to %q", name, merged.Image, e.svc.Image))
				}
				merged.Image = e.svc.Image
			}

			merged.Ports = append(merged.Ports, e.svc.Ports...)
			merged.Volumes = append(merged.Volumes, e.svc.Volumes...)

			for _, env := range e.svc.Environment {
				parts := strings.SplitN(env, "=", 2)
				if len(parts) < 2 {
					continue
				}
				if prev, ok := merged.Environment[parts[0]]; ok && prev != parts[1] {
					merged.Overrides = append(merged.Overrides, Override{
						Field:  "environment:" + parts[0],
						FileA:  sources[0],
						FileB:  e.file,
						ValueA: prev,
						ValueB: parts[1],
					})
					warnings = append(warnings, fmt.Sprintf("service %q: env %s overridden from %q to %q", name, parts[0], prev, parts[1]))
				}
				merged.Environment[parts[0]] = parts[1]
			}
		}
		merged.Sources = sources

		volSeen := map[string]bool{}
		var deduped []string
		for _, v := range merged.Volumes {
			if !volSeen[v] {
				volSeen[v] = true
				deduped = append(deduped, v)
			}
		}
		merged.Volumes = deduped

		services = append(services, merged)
	}

	return MergeResult{
		Path:     collected.Root,
		Services: services,
		Warnings: warnings,
	}
}

func FormatText(r MergeResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Merge Check: %s — %d service(s)\n\n", r.Path, len(r.Services))

	for _, svc := range r.Services {
		fmt.Fprintf(&b, "  %s", svc.Name)
		if svc.Image != "" {
			fmt.Fprintf(&b, " (%s)", svc.Image)
		}
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "    sources: %s\n", strings.Join(svc.Sources, ", "))

		if len(svc.Ports) > 0 {
			var portStrs []string
			for _, p := range svc.Ports {
				portStrs = append(portStrs, p.Raw)
			}
			fmt.Fprintf(&b, "    ports: %s\n", strings.Join(portStrs, ", "))
		}
		if len(svc.Volumes) > 0 {
			fmt.Fprintf(&b, "    volumes: %s\n", strings.Join(svc.Volumes, ", "))
		}
		if len(svc.Environment) > 0 {
			var envStrs []string
			for k, v := range svc.Environment {
				envStrs = append(envStrs, k+"="+v)
			}
			fmt.Fprintf(&b, "    env: %s\n", strings.Join(envStrs, ", "))
		}
		if len(svc.Overrides) > 0 {
			fmt.Fprintf(&b, "    overrides:\n")
			for _, o := range svc.Overrides {
				fmt.Fprintf(&b, "      %s: %q -> %q (%s overrides %s)\n", o.Field, o.ValueA, o.ValueB, o.FileB, o.FileA)
			}
		}
		b.WriteByte('\n')
	}

	if len(r.Warnings) > 0 {
		fmt.Fprintf(&b, "Warnings:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  - %s\n", w)
		}
	}
	return b.String()
}

func FormatJSON(r MergeResult) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
