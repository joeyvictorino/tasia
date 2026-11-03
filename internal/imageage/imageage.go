package imageage

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type Staleness string

const (
	StaleEOL     Staleness = "eol"
	StaleOld     Staleness = "old"
	StaleCurrent Staleness = "current"
	StaleUnknown Staleness = "unknown"
)

type ImageAnalysis struct {
	Service   string    `json:"service"`
	File      string    `json:"file"`
	Image     string    `json:"image"`
	Registry  string    `json:"registry,omitempty"`
	Name      string    `json:"name"`
	Tag       string    `json:"tag"`
	MajorVer  int       `json:"major_version,omitempty"`
	MinorVer  int       `json:"minor_version,omitempty"`
	Staleness Staleness `json:"staleness"`
	Reason    string    `json:"reason"`
}

type Report struct {
	Images  []ImageAnalysis `json:"images"`
	Summary Summary         `json:"summary"`
}

type Summary struct {
	TotalImages  int            `json:"total_images"`
	ByStaleness  map[string]int `json:"by_staleness"`
	UniqueImages int            `json:"unique_images"`
	NoTag        int            `json:"no_tag"`
	LatestTag    int            `json:"latest_tag"`
}

var eolImages = map[string]int{
	"python":   2,
	"node":     16,
	"ruby":     2,
	"golang":   1,
	"php":      7,
	"postgres": 12,
	"mysql":    5,
	"redis":    6,
	"nginx":    1,
	"ubuntu":   20,
	"debian":   10,
	"alpine":   3,
}

var oldThresholds = map[string]int{
	"python":   3,
	"node":     18,
	"ruby":     3,
	"golang":   1,
	"php":      8,
	"postgres": 14,
	"mysql":    8,
	"redis":    7,
	"nginx":    1,
	"ubuntu":   22,
	"debian":   11,
	"alpine":   3,
}

var semverRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?`)

func Analyze(collected *collect.Collected) Report {
	var images []ImageAnalysis
	seen := map[string]bool{}

	for _, cf := range collected.ComposeFiles {
		for i := range cf.Services {
			svc := &cf.Services[i]
			if svc.Image == "" {
				continue
			}
			ia := analyzeImage(svc.Image, svc.Name, cf.Path)
			images = append(images, ia)
			seen[svc.Image] = true
		}
	}

	sort.Slice(images, func(i, j int) bool {
		if images[i].Staleness != images[j].Staleness {
			return stalenessRank(images[i].Staleness) > stalenessRank(images[j].Staleness)
		}
		return images[i].Service < images[j].Service
	})

	byStaleness := map[string]int{}
	noTag := 0
	latestTag := 0
	for _, ia := range images {
		byStaleness[string(ia.Staleness)]++
		if ia.Tag == "" {
			noTag++
		}
		if ia.Tag == "latest" {
			latestTag++
		}
	}

	return Report{
		Images: images,
		Summary: Summary{
			TotalImages:  len(images),
			ByStaleness:  byStaleness,
			UniqueImages: len(seen),
			NoTag:        noTag,
			LatestTag:    latestTag,
		},
	}
}

func analyzeImage(image, service, file string) ImageAnalysis {
	registry, name, tag := parseImageRef(image)

	ia := ImageAnalysis{
		Service:  service,
		File:     file,
		Image:    image,
		Registry: registry,
		Name:     name,
		Tag:      tag,
	}

	if tag == "" || tag == "latest" {
		ia.Staleness = StaleUnknown
		if tag == "" {
			ia.Reason = "no tag specified, cannot determine age"
		} else {
			ia.Reason = "latest tag is mutable, cannot determine age"
		}
		return ia
	}

	baseName := name
	if idx := strings.LastIndex(baseName, "/"); idx >= 0 {
		baseName = baseName[idx+1:]
	}

	m := semverRe.FindStringSubmatch(tag)
	if m == nil {
		ia.Staleness = StaleUnknown
		ia.Reason = "non-semver tag, cannot determine age"
		return ia
	}

	major, _ := strconv.Atoi(m[1])
	ia.MajorVer = major
	if m[2] != "" {
		minor, _ := strconv.Atoi(m[2])
		ia.MinorVer = minor
	}

	if eolMax, ok := eolImages[baseName]; ok && major <= eolMax {
		ia.Staleness = StaleEOL
		ia.Reason = fmt.Sprintf("%s %d.x is end-of-life", baseName, major)
		return ia
	}

	if oldMax, ok := oldThresholds[baseName]; ok && major <= oldMax {
		ia.Staleness = StaleOld
		ia.Reason = fmt.Sprintf("%s %d.x is outdated, consider upgrading", baseName, major)
		return ia
	}

	ia.Staleness = StaleCurrent
	ia.Reason = "tag appears current"
	return ia
}

func parseImageRef(image string) (registry, name, tag string) {
	ref := image
	if strings.Contains(ref, "://") {
		ref = strings.SplitN(ref, "://", 2)[1]
	}

	parts := strings.SplitN(ref, "/", 3)
	switch len(parts) {
	case 3:
		registry = parts[0]
		name = parts[1] + "/" + parts[2]
	case 2:
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
			registry = parts[0]
			name = parts[1]
		} else {
			name = ref
		}
	default:
		name = ref
	}

	if idx := strings.LastIndex(name, ":"); idx >= 0 {
		tag = name[idx+1:]
		name = name[:idx]
	}

	if idx := strings.Index(name, "@"); idx >= 0 {
		name = name[:idx]
	}

	return registry, name, tag
}

func stalenessRank(s Staleness) int {
	switch s {
	case StaleEOL:
		return 3
	case StaleOld:
		return 2
	case StaleUnknown:
		return 1
	default:
		return 0
	}
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Image Age Analysis (%d images, %d unique)\n\n",
		r.Summary.TotalImages, r.Summary.UniqueImages)

	if r.Summary.NoTag > 0 {
		fmt.Fprintf(&b, "  Warning: %d images have no tag\n", r.Summary.NoTag)
	}
	if r.Summary.LatestTag > 0 {
		fmt.Fprintf(&b, "  Warning: %d images use :latest tag\n", r.Summary.LatestTag)
	}
	if r.Summary.NoTag > 0 || r.Summary.LatestTag > 0 {
		b.WriteString("\n")
	}

	for _, ia := range r.Images {
		icon := "  "
		switch ia.Staleness {
		case StaleEOL:
			icon = "!!"
		case StaleOld:
			icon = "! "
		case StaleUnknown:
			icon = "? "
		}
		fmt.Fprintf(&b, "  %s %-20s %-30s [%s]\n", icon, ia.Service, ia.Image, ia.Staleness)
		fmt.Fprintf(&b, "       %s\n", ia.Reason)
	}

	if len(r.Summary.ByStaleness) > 0 {
		b.WriteString("\n  Summary:\n")
		for _, s := range []Staleness{StaleEOL, StaleOld, StaleUnknown, StaleCurrent} {
			if count, ok := r.Summary.ByStaleness[string(s)]; ok {
				fmt.Fprintf(&b, "    %-10s %d\n", s, count)
			}
		}
	}

	b.WriteString("\n")
	return b.String()
}
