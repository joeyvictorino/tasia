package collect

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// KubeManifest holds one parsed Kubernetes resource with security-relevant fields.
type KubeManifest struct {
	Path       string
	Kind       string // Deployment, Pod, StatefulSet, DaemonSet, Service, etc.
	Name       string
	Namespace  string
	Containers []KubeContainer
	// Service-specific
	ServiceType string   // ClusterIP, NodePort, LoadBalancer
	ServicePorts []KubeServicePort
	// Pod-level
	HostNetwork bool
	HostNetworkLine int
}

// KubeContainer holds security-relevant fields for one container in a pod spec.
type KubeContainer struct {
	Name       string
	Image      string
	ImageLine  int
	Privileged bool
	PrivilegedLine int
	RunAsRoot  bool // explicit runAsUser: 0 or runAsNonRoot: false
	RunAsRootLine int
	RunAsNonRootSet bool
	RunAsUser  *int64
	HostPathMounts []KubeHostPathMount
}

// KubeHostPathMount records a hostPath volume mount.
type KubeHostPathMount struct {
	MountPath string
	HostPath  string
	ReadOnly  bool
	Line      int
}

// KubeServicePort records one port in a Service spec.
type KubeServicePort struct {
	Port       int
	TargetPort int
	NodePort   int
	Line       int
}

// ParseKubeYAML parses one or more Kubernetes resources from a YAML file.
// It handles multi-document YAML (separated by ---).
func ParseKubeYAML(path, content string) ([]KubeManifest, error) {
	var manifests []KubeManifest

	docs := splitYAMLDocs(content)
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		var node yaml.Node
		if err := yaml.Unmarshal([]byte(doc), &node); err != nil {
			continue
		}
		if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
			continue
		}
		root := node.Content[0]
		if root.Kind != yaml.MappingNode {
			continue
		}

		m := parseManifestNode(path, root)
		if m.Kind == "" {
			continue
		}
		manifests = append(manifests, m)
	}
	return manifests, nil
}

func splitYAMLDocs(content string) []string {
	var docs []string
	var current strings.Builder
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "---" {
			if current.Len() > 0 {
				docs = append(docs, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")
	}
	if current.Len() > 0 {
		docs = append(docs, current.String())
	}
	return docs
}

func parseManifestNode(path string, root *yaml.Node) KubeManifest {
	m := KubeManifest{Path: path}

	fields := mapFields(root)

	if kindNode, ok := fields["kind"]; ok {
		m.Kind = kindNode.Value
	}

	if metaNode, ok := fields["metadata"]; ok && metaNode.Kind == yaml.MappingNode {
		metaFields := mapFields(metaNode)
		if n, ok := metaFields["name"]; ok {
			m.Name = n.Value
		}
		if n, ok := metaFields["namespace"]; ok {
			m.Namespace = n.Value
		}
	}

	switch m.Kind {
	case "Service":
		parseServiceSpec(fields, &m)
	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		if specNode, ok := fields["spec"]; ok && specNode.Kind == yaml.MappingNode {
			specFields := mapFields(specNode)
			if tplNode, ok := specFields["template"]; ok && tplNode.Kind == yaml.MappingNode {
				tplFields := mapFields(tplNode)
				if podSpecNode, ok := tplFields["spec"]; ok {
					parsePodSpec(podSpecNode, &m)
				}
			}
		}
	case "Pod":
		if specNode, ok := fields["spec"]; ok {
			parsePodSpec(specNode, &m)
		}
	case "CronJob":
		if specNode, ok := fields["spec"]; ok && specNode.Kind == yaml.MappingNode {
			specFields := mapFields(specNode)
			if jtNode, ok := specFields["jobTemplate"]; ok && jtNode.Kind == yaml.MappingNode {
				jtFields := mapFields(jtNode)
				if innerSpec, ok := jtFields["spec"]; ok && innerSpec.Kind == yaml.MappingNode {
					innerFields := mapFields(innerSpec)
					if tplNode, ok := innerFields["template"]; ok && tplNode.Kind == yaml.MappingNode {
						tplFields := mapFields(tplNode)
						if podSpec, ok := tplFields["spec"]; ok {
							parsePodSpec(podSpec, &m)
						}
					}
				}
			}
		}
	}

	return m
}

func parseServiceSpec(fields map[string]*yaml.Node, m *KubeManifest) {
	specNode, ok := fields["spec"]
	if !ok || specNode.Kind != yaml.MappingNode {
		return
	}
	specFields := mapFields(specNode)
	if t, ok := specFields["type"]; ok {
		m.ServiceType = t.Value
	}
	if portsNode, ok := specFields["ports"]; ok && portsNode.Kind == yaml.SequenceNode {
		for _, pn := range portsNode.Content {
			if pn.Kind != yaml.MappingNode {
				continue
			}
			sp := KubeServicePort{Line: pn.Line}
			pf := mapFields(pn)
			if v, ok := pf["port"]; ok {
				sp.Port = intFromNode(v)
			}
			if v, ok := pf["targetPort"]; ok {
				sp.TargetPort = intFromNode(v)
			}
			if v, ok := pf["nodePort"]; ok {
				sp.NodePort = intFromNode(v)
			}
			m.ServicePorts = append(m.ServicePorts, sp)
		}
	}
}

func parsePodSpec(specNode *yaml.Node, m *KubeManifest) {
	if specNode.Kind != yaml.MappingNode {
		return
	}
	specFields := mapFields(specNode)

	if hn, ok := specFields["hostNetwork"]; ok && hn.Value == "true" {
		m.HostNetwork = true
		m.HostNetworkLine = hn.Line
	}

	// Collect hostPath volumes by name for cross-referencing with mounts.
	hostPaths := map[string]string{}
	if volsNode, ok := specFields["volumes"]; ok && volsNode.Kind == yaml.SequenceNode {
		for _, vn := range volsNode.Content {
			if vn.Kind != yaml.MappingNode {
				continue
			}
			vf := mapFields(vn)
			nameNode, hasName := vf["name"]
			hpNode, hasHP := vf["hostPath"]
			if hasName && hasHP && hpNode.Kind == yaml.MappingNode {
				hpFields := mapFields(hpNode)
				if p, ok := hpFields["path"]; ok {
					hostPaths[nameNode.Value] = p.Value
				}
			}
		}
	}

	parseContainers := func(key string) {
		cNode, ok := specFields[key]
		if !ok || cNode.Kind != yaml.SequenceNode {
			return
		}
		for _, cn := range cNode.Content {
			if cn.Kind != yaml.MappingNode {
				continue
			}
			kc := parseContainerNode(cn, hostPaths)
			m.Containers = append(m.Containers, kc)
		}
	}
	parseContainers("containers")
	parseContainers("initContainers")
}

func parseContainerNode(cn *yaml.Node, hostPaths map[string]string) KubeContainer {
	kc := KubeContainer{}
	cf := mapFields(cn)

	if n, ok := cf["name"]; ok {
		kc.Name = n.Value
	}
	if n, ok := cf["image"]; ok {
		kc.Image = n.Value
		kc.ImageLine = n.Line
	}

	if sc, ok := cf["securityContext"]; ok && sc.Kind == yaml.MappingNode {
		scf := mapFields(sc)
		if p, ok := scf["privileged"]; ok && p.Value == "true" {
			kc.Privileged = true
			kc.PrivilegedLine = p.Line
		}
		if u, ok := scf["runAsUser"]; ok {
			uid := int64(intFromNode(u))
			kc.RunAsUser = &uid
			if uid == 0 {
				kc.RunAsRoot = true
				kc.RunAsRootLine = u.Line
			}
		}
		if nr, ok := scf["runAsNonRoot"]; ok {
			kc.RunAsNonRootSet = true
			if nr.Value == "false" {
				kc.RunAsRoot = true
				kc.RunAsRootLine = nr.Line
			}
		}
	}

	if mounts, ok := cf["volumeMounts"]; ok && mounts.Kind == yaml.SequenceNode {
		for _, mn := range mounts.Content {
			if mn.Kind != yaml.MappingNode {
				continue
			}
			mf := mapFields(mn)
			var mount KubeHostPathMount
			mount.Line = mn.Line
			if n, ok := mf["mountPath"]; ok {
				mount.MountPath = n.Value
			}
			if n, ok := mf["readOnly"]; ok && n.Value == "true" {
				mount.ReadOnly = true
			}
			if n, ok := mf["name"]; ok {
				if hp, found := hostPaths[n.Value]; found {
					mount.HostPath = hp
					kc.HostPathMounts = append(kc.HostPathMounts, mount)
				}
			}
		}
	}

	return kc
}

// mapFields converts a MappingNode's children to a key->value map.
func mapFields(n *yaml.Node) map[string]*yaml.Node {
	m := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		m[n.Content[i].Value] = n.Content[i+1]
	}
	return m
}

func intFromNode(n *yaml.Node) int {
	var v int
	_ = n.Decode(&v)
	return v
}

// IsKubeFile returns true if a filename looks like a Kubernetes manifest.
func IsKubeFile(name, content string) bool {
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
		return false
	}
	return strings.Contains(content, "apiVersion:") && strings.Contains(content, "kind:")
}
