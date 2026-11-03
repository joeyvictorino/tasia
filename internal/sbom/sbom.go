package sbom

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	Source  string `json:"source"`
	License string `json:"license,omitempty"`
	PkgURL  string `json:"purl,omitempty"`
}

type SBOM struct {
	Format     string      `json:"format"`
	Timestamp  string      `json:"timestamp"`
	ScanPath   string      `json:"scan_path"`
	Components []Component `json:"components"`
	Summary    SBOMSummary `json:"summary"`
}

type SBOMSummary struct {
	Total    int            `json:"total"`
	ByType   map[string]int `json:"by_type"`
	Unpinned int            `json:"unpinned"`
}

var semverRe = regexp.MustCompile(`^v?\d+(\.\d+)*$`)
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func GenerateSBOM(scanPath string, c *collect.Collected) SBOM {
	s := SBOM{
		Format:    "tasia-sbom-1.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		ScanPath:  scanPath,
	}

	seen := map[string]bool{}

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if svc.Image == "" {
				continue
			}
			img, tag := parseImageRef(svc.Image)
			key := fmt.Sprintf("docker:%s:%s", img, tag)
			if seen[key] {
				continue
			}
			seen[key] = true

			comp := Component{
				Name:    img,
				Version: tag,
				Type:    "container-image",
				Source:  cf.Path,
			}
			if tag != "" {
				comp.PkgURL = fmt.Sprintf("pkg:docker/%s@%s", img, tag)
			} else {
				comp.PkgURL = fmt.Sprintf("pkg:docker/%s", img)
			}
			s.Components = append(s.Components, comp)
		}
	}

	for _, hv := range c.HelmValues {
		for _, f := range hv.Findings {
			if strings.HasSuffix(f.KeyPath, ".repository") || strings.HasSuffix(f.KeyPath, ".image") {
				chart, ver := parseHelmRef(f.Value)
				key := fmt.Sprintf("helm:%s:%s", chart, ver)
				if seen[key] {
					continue
				}
				seen[key] = true
				comp := Component{
					Name:    chart,
					Version: ver,
					Type:    "helm-chart",
					Source:  hv.Path,
				}
				if ver != "" {
					comp.PkgURL = fmt.Sprintf("pkg:helm/%s@%s", chart, ver)
				}
				s.Components = append(s.Components, comp)
			}
		}
	}

	for _, tf := range c.TerraformFiles {
		provs := extractTerraformProviders(tf)
		for _, p := range provs {
			key := fmt.Sprintf("tf:%s:%s:%s", p.Type, p.Name, p.Version)
			if seen[key] {
				continue
			}
			seen[key] = true
			s.Components = append(s.Components, p)
		}
	}

	byType := map[string]int{}
	unpinned := 0
	for _, c := range s.Components {
		byType[c.Type]++
		if !isPinned(c.Version) {
			unpinned++
		}
	}
	s.Summary = SBOMSummary{
		Total:    len(s.Components),
		ByType:   byType,
		Unpinned: unpinned,
	}
	return s
}

func parseImageRef(ref string) (image, tag string) {
	if at := strings.LastIndex(ref, "@"); at > 0 {
		return ref[:at], ref[at+1:]
	}
	if colon := strings.LastIndex(ref, ":"); colon > 0 {
		after := ref[colon+1:]
		if !strings.Contains(after, "/") {
			return ref[:colon], after
		}
	}
	return ref, ""
}

func parseHelmRef(val string) (name, version string) {
	parts := strings.SplitN(val, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return val, ""
}

func extractTerraformProviders(tf collect.TerraformFile) []Component {
	var comps []Component

	provRe := regexp.MustCompile(`(?m)^\s*source\s*=\s*"([^"]+)"`)
	verRe := regexp.MustCompile(`(?m)^\s*version\s*=\s*"([^"]+)"`)

	content := readTFContent(tf)

	provMatches := provRe.FindAllStringSubmatch(content, -1)
	verMatches := verRe.FindAllStringSubmatch(content, -1)

	verMap := map[int]string{}
	for _, m := range verMatches {
		idx := strings.Index(content, m[0])
		verMap[idx] = m[1]
	}

	for _, m := range provMatches {
		source := m[1]
		parts := strings.Split(source, "/")
		name := source
		if len(parts) >= 2 {
			name = parts[len(parts)-1]
		}

		pType := "terraform-provider"
		if strings.Contains(source, "//") || strings.Contains(source, "modules") {
			pType = "terraform-module"
		}

		ver := ""
		idx := strings.Index(content, m[0])
		for vi, vv := range verMap {
			if vi > idx && vi-idx < 200 {
				ver = vv
				break
			}
		}

		comp := Component{
			Name:    name,
			Version: ver,
			Type:    pType,
			Source:  tf.Path,
		}
		if ver != "" {
			comp.PkgURL = fmt.Sprintf("pkg:terraform/%s@%s", source, ver)
		} else {
			comp.PkgURL = fmt.Sprintf("pkg:terraform/%s", source)
		}
		comps = append(comps, comp)
	}

	return comps
}

func readTFContent(tf collect.TerraformFile) string {
	var sb strings.Builder
	for _, sg := range tf.SecurityGroups {
		sb.WriteString(sg.ResourceName + " ")
	}
	for _, b := range tf.S3Buckets {
		sb.WriteString(b.ResourceName + " ")
	}
	return sb.String()
}

func isPinned(version string) bool {
	if version == "" || version == "latest" {
		return false
	}
	if digestRe.MatchString(version) {
		return true
	}
	if semverRe.MatchString(version) {
		return true
	}
	return false
}

func FormatText(s SBOM) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Software Bill of Materials (%d components, %d unpinned)\n\n", s.Summary.Total, s.Summary.Unpinned))
	sb.WriteString(fmt.Sprintf("  %-35s %-15s %-20s %s\n", "COMPONENT", "VERSION", "TYPE", "SOURCE"))
	sb.WriteString(fmt.Sprintf("  %-35s %-15s %-20s %s\n", strings.Repeat("-", 35), strings.Repeat("-", 15), strings.Repeat("-", 20), strings.Repeat("-", 20)))
	for _, c := range s.Components {
		ver := c.Version
		if ver == "" {
			ver = "(unpinned)"
		}
		sb.WriteString(fmt.Sprintf("  %-35s %-15s %-20s %s\n", c.Name, ver, c.Type, c.Source))
	}
	if s.Summary.Total == 0 {
		sb.WriteString("  No components found.\n")
	}
	sb.WriteString(fmt.Sprintf("\nSummary: %d total", s.Summary.Total))
	for t, n := range s.Summary.ByType {
		sb.WriteString(fmt.Sprintf(", %d %s", n, t))
	}
	sb.WriteString("\n")
	return sb.String()
}

type SPDXLite struct {
	SPDXVersion    string        `json:"spdxVersion"`
	DataLicense    string        `json:"dataLicense"`
	SPDXID         string        `json:"SPDXID"`
	Name           string        `json:"name"`
	DocumentNS     string        `json:"documentNamespace"`
	CreationInfo   SPDXCreation  `json:"creationInfo"`
	Packages       []SPDXPackage `json:"packages"`
}

type SPDXCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type SPDXPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
}

type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

func ToSPDXLite(s SBOM) SPDXLite {
	spdx := SPDXLite{
		SPDXVersion: "SPDX-2.3",
		DataLicense: "CC0-1.0",
		SPDXID:      "SPDXRef-DOCUMENT",
		Name:        "tasia-sbom",
		DocumentNS:  fmt.Sprintf("https://tasia.dev/sbom/%s", s.Timestamp),
		CreationInfo: SPDXCreation{
			Created:  s.Timestamp,
			Creators: []string{"Tool: tasia"},
		},
	}
	for i, c := range s.Components {
		pkg := SPDXPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: "NOASSERTION",
		}
		if c.PkgURL != "" {
			pkg.ExternalRefs = []SPDXExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  c.PkgURL,
			}}
		}
		spdx.Packages = append(spdx.Packages, pkg)
	}
	return spdx
}
