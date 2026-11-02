package volumeaudit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type SharedVolume struct {
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Services []string `json:"services"`
	Files    []string `json:"files"`
	Writable bool     `json:"writable"`
}

type OverlapPair struct {
	ServiceA string `json:"service_a"`
	ServiceB string `json:"service_b"`
	VolumeA  string `json:"volume_a"`
	VolumeB  string `json:"volume_b"`
	Overlap  string `json:"overlap"`
}

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Volume   string `json:"volume"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Report struct {
	Path          string         `json:"path"`
	SharedVolumes []SharedVolume `json:"shared_volumes"`
	Overlaps      []OverlapPair  `json:"overlaps"`
	Findings      []Finding      `json:"findings"`
	Summary       Summary        `json:"summary"`
}

type Summary struct {
	ServicesScanned int `json:"services_scanned"`
	VolumesScanned  int `json:"volumes_scanned"`
	SharedCount     int `json:"shared_count"`
	OverlapCount    int `json:"overlap_count"`
	FindingCount    int `json:"finding_count"`
}

type mountEntry struct {
	service string
	file    string
	source  string
	target  string
	ro      bool
	raw     string
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	var entries []mountEntry
	svcCount := 0

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			svcCount++
			for _, v := range svc.Volumes {
				me := parseMount(v, svc.Name, cf.Path)
				entries = append(entries, me)
			}
			checkServiceVolumes(svc, cf.Path, &r)
		}
	}

	findShared(entries, &r)
	findOverlaps(entries, &r)
	checkPersistence(entries, &r)

	r.Summary = Summary{
		ServicesScanned: svcCount,
		VolumesScanned:  len(entries),
		SharedCount:     len(r.SharedVolumes),
		OverlapCount:    len(r.Overlaps),
		FindingCount:    len(r.Findings),
	}

	sort.Slice(r.Findings, func(i, j int) bool {
		return sevOrder(r.Findings[i].Severity) < sevOrder(r.Findings[j].Severity)
	})

	return r
}

func parseMount(spec, service, file string) mountEntry {
	me := mountEntry{service: service, file: file, raw: spec}
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) >= 2 {
		me.source = parts[0]
		me.target = parts[1]
		if len(parts) == 3 && strings.Contains(parts[2], "ro") {
			me.ro = true
		}
	} else if len(parts) == 1 {
		me.target = parts[0]
	}
	return me
}

func isBindMount(source string) bool {
	return strings.HasPrefix(source, "/") || strings.HasPrefix(source, ".") || strings.HasPrefix(source, "~")
}

func checkServiceVolumes(svc compose.Service, file string, r *Report) {
	for _, v := range svc.Volumes {
		me := parseMount(v, svc.Name, file)

		if me.source == "/var/run/docker.sock" && !me.ro {
			r.Findings = append(r.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Volume:   v,
				Category: "writable_docker_socket",
				Severity: "critical",
				Message:  "Docker socket mounted writable; enables full host escape. Mount with :ro if only read access is needed",
			})
		}

		if isBindMount(me.source) && !me.ro && isRootMount(me.target) {
			r.Findings = append(r.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Volume:   v,
				Category: "root_target_writable",
				Severity: "high",
				Message:  fmt.Sprintf("Host path mounted writable at container root-level target %s", me.target),
			})
		}

		if me.source != "" && me.target != "" && me.source == me.target && isBindMount(me.source) && !me.ro {
			r.Findings = append(r.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Volume:   v,
				Category: "identity_mount",
				Severity: "medium",
				Message:  fmt.Sprintf("Host path %s mounted at identical container path writable; changes propagate bidirectionally", me.source),
			})
		}
	}
}

func findShared(entries []mountEntry, r *Report) {
	type key struct{ source, target string }
	groups := map[key][]mountEntry{}
	for _, e := range entries {
		if e.source == "" {
			continue
		}
		k := key{source: e.source, target: e.target}
		groups[k] = append(groups[k], e)
	}

	var keys []key
	for k, group := range groups {
		if len(group) < 2 {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		return keys[i].target < keys[j].target
	})

	for _, k := range keys {
		group := groups[k]
		sv := SharedVolume{Source: k.source, Target: k.target}
		seen := map[string]bool{}
		filesSeen := map[string]bool{}
		allRO := true
		for _, e := range group {
			if !seen[e.service] {
				sv.Services = append(sv.Services, e.service)
				seen[e.service] = true
			}
			if !filesSeen[e.file] {
				sv.Files = append(sv.Files, e.file)
				filesSeen[e.file] = true
			}
			if !e.ro {
				allRO = false
			}
		}
		sv.Writable = !allRO
		r.SharedVolumes = append(r.SharedVolumes, sv)

		if sv.Writable && len(sv.Services) >= 2 {
			r.Findings = append(r.Findings, Finding{
				Service:  strings.Join(sv.Services, ", "),
				File:     strings.Join(sv.Files, ", "),
				Volume:   sv.Source,
				Category: "shared_writable_volume",
				Severity: "high",
				Message:  fmt.Sprintf("Volume %s shared writable between %d services; data corruption risk", sv.Source, len(sv.Services)),
			})
		}
	}
}

func findOverlaps(entries []mountEntry, r *Report) {
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			a, b := entries[i], entries[j]
			if a.service == b.service {
				continue
			}
			if a.source == "" || b.source == "" {
				continue
			}
			if !isBindMount(a.source) || !isBindMount(b.source) {
				continue
			}
			overlap := pathOverlap(a.source, b.source)
			if overlap != "" && a.source != b.source {
				r.Overlaps = append(r.Overlaps, OverlapPair{
					ServiceA: a.service,
					ServiceB: b.service,
					VolumeA:  a.raw,
					VolumeB:  b.raw,
					Overlap:  overlap,
				})
				r.Findings = append(r.Findings, Finding{
					Service:  a.service + ", " + b.service,
					File:     a.file,
					Volume:   a.raw + " / " + b.raw,
					Category: "path_overlap",
					Severity: "medium",
					Message:  fmt.Sprintf("Overlapping bind mounts: %s and %s share prefix %s", a.source, b.source, overlap),
				})
			}
		}
	}
}

func pathOverlap(a, b string) string {
	if strings.HasPrefix(b, a+"/") {
		return a
	}
	if strings.HasPrefix(a, b+"/") {
		return b
	}
	return ""
}

func checkPersistence(entries []mountEntry, r *Report) {
	for _, e := range entries {
		if e.source == "" && e.target != "" {
			r.Findings = append(r.Findings, Finding{
				Service:  e.service,
				File:     e.file,
				Volume:   e.raw,
				Category: "anonymous_no_persistence",
				Severity: "low",
				Message:  fmt.Sprintf("Anonymous volume at %s has no persistence guarantee; data lost on container removal", e.target),
			})
		}
	}
}

func isRootMount(target string) bool {
	rootTargets := []string{"/", "/bin", "/sbin", "/lib", "/usr", "/etc", "/var", "/opt"}
	for _, rt := range rootTargets {
		if target == rt {
			return true
		}
	}
	return false
}

func sevOrder(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Volume Audit Report\n")
	fmt.Fprintf(&b, "%s\n\n", strings.Repeat("=", 62))

	if r.Summary.VolumesScanned == 0 {
		fmt.Fprintln(&b, "  No volume mounts found.")
		return b.String()
	}

	fmt.Fprintf(&b, "  Services scanned:  %d\n", r.Summary.ServicesScanned)
	fmt.Fprintf(&b, "  Volumes scanned:   %d\n", r.Summary.VolumesScanned)
	fmt.Fprintf(&b, "  Shared volumes:    %d\n", r.Summary.SharedCount)
	fmt.Fprintf(&b, "  Path overlaps:     %d\n", r.Summary.OverlapCount)
	fmt.Fprintf(&b, "  Findings:          %d\n\n", r.Summary.FindingCount)

	if len(r.SharedVolumes) > 0 {
		fmt.Fprintf(&b, "Shared Volumes\n%s\n", strings.Repeat("-", 62))
		for _, sv := range r.SharedVolumes {
			rw := "ro"
			if sv.Writable {
				rw = "rw"
			}
			fmt.Fprintf(&b, "  %s -> %s [%s] shared by: %s\n",
				sv.Source, sv.Target, rw, strings.Join(sv.Services, ", "))
		}
		fmt.Fprintln(&b)
	}

	if len(r.Findings) > 0 {
		fmt.Fprintf(&b, "Findings\n%s\n", strings.Repeat("-", 62))
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "  [%s] %s: %s\n", strings.ToUpper(f.Severity), f.Category, f.Message)
			fmt.Fprintf(&b, "    service: %s  volume: %s\n\n", f.Service, f.Volume)
		}
	}

	return b.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data)
}
