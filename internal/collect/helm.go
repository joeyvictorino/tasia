package collect

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// HelmValues holds security-relevant defaults extracted from a Helm values.yaml.
type HelmValues struct {
	Path     string
	Findings []HelmValueFinding
}

// HelmValueFinding records one security-relevant value in a Helm values.yaml.
type HelmValueFinding struct {
	KeyPath string // dot-separated path like "service.type"
	Value   string
	Line    int
}

// ParseHelmValues scans a values.yaml for security-relevant defaults.
func ParseHelmValues(path, content string) HelmValues {
	hv := HelmValues{Path: path}

	var node yaml.Node
	if err := yaml.Unmarshal([]byte(content), &node); err != nil {
		return hv
	}
	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		return hv
	}
	root := node.Content[0]
	if root.Kind != yaml.MappingNode {
		return hv
	}

	walkHelmValues(root, "", &hv)
	return hv
}

func walkHelmValues(n *yaml.Node, prefix string, hv *HelmValues) {
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i]
		val := n.Content[i+1]
		fullKey := key.Value
		if prefix != "" {
			fullKey = prefix + "." + key.Value
		}

		if val.Kind == yaml.MappingNode {
			walkHelmValues(val, fullKey, hv)
			continue
		}

		if val.Kind != yaml.ScalarNode {
			continue
		}

		if isHelmSecurityKey(fullKey, val.Value) {
			hv.Findings = append(hv.Findings, HelmValueFinding{
				KeyPath: fullKey,
				Value:   val.Value,
				Line:    val.Line,
			})
		}
	}
}

func isHelmSecurityKey(keyPath, value string) bool {
	lower := strings.ToLower(keyPath)
	lowerVal := strings.ToLower(value)

	// Service type
	if strings.HasSuffix(lower, "service.type") || strings.HasSuffix(lower, "servicetype") {
		return lowerVal == "loadbalancer" || lowerVal == "nodeport"
	}

	// Privileged
	if strings.HasSuffix(lower, "privileged") {
		return lowerVal == "true"
	}

	// Run as root
	if strings.HasSuffix(lower, "runasuser") {
		return value == "0"
	}
	if strings.HasSuffix(lower, "runasnonroot") {
		return lowerVal == "false"
	}

	// Host network
	if strings.HasSuffix(lower, "hostnetwork") {
		return lowerVal == "true"
	}

	// Host path
	if strings.HasSuffix(lower, "hostpath") && value != "" && value != "/" {
		return true
	}

	return false
}

// IsHelmValuesFile returns true if the file is a Helm values.yaml in a chart
// directory (contains Chart.yaml sibling).
func IsHelmValuesFile(name string) bool {
	lower := strings.ToLower(name)
	return lower == "values.yaml" || lower == "values.yml"
}
