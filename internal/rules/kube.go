package rules

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func kubeFindings(manifests []collect.KubeManifest) []Finding {
	var out []Finding
	for _, m := range manifests {
		out = append(out, kubeServiceFindings(m)...)
		out = append(out, kubeContainerFindings(m)...)
		out = append(out, kubeHostNetworkFindings(m)...)
	}
	return out
}

func kubeServiceFindings(m collect.KubeManifest) []Finding {
	if m.Kind != "Service" {
		return nil
	}
	var out []Finding
	svcType := strings.ToLower(m.ServiceType)
	if svcType != "loadbalancer" && svcType != "nodeport" {
		return nil
	}

	for _, sp := range m.ServicePorts {
		out = append(out, Finding{
			ID:       "kube_exposed_service",
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("Kubernetes Service %q type %s exposes port %d", m.Name, m.ServiceType, sp.Port),
			File:     m.Path,
			Line:     sp.Line,
			Evidence: fmt.Sprintf("kind=Service name=%s type=%s port=%d", m.Name, m.ServiceType, sp.Port),
			Why:      "A LoadBalancer or NodePort Service makes the backing pods reachable from outside the cluster. AI inference, vector DB and agent-runtime pods should stay behind ClusterIP or an ingress with authentication.",
			Fix:      "Change the Service type to ClusterIP and expose through an authenticated ingress controller, or restrict access with NetworkPolicy.",
		})
	}
	return out
}

func kubeContainerFindings(m collect.KubeManifest) []Finding {
	if m.Kind == "Service" {
		return nil
	}
	var out []Finding
	for _, c := range m.Containers {
		if c.Privileged {
			out = append(out, Finding{
				ID:       "kube_privileged",
				Severity: SeverityCritical,
				Title:    fmt.Sprintf("Container %q in %s %q runs privileged", c.Name, m.Kind, m.Name),
				File:     m.Path,
				Line:     c.PrivilegedLine,
				Evidence: fmt.Sprintf("container=%s securityContext.privileged=true", c.Name),
				Why:      "A privileged container has full access to the host kernel. A model or agent running inside it can escape the container trivially.",
				Fix:      "Remove securityContext.privileged or set it to false. Use specific capabilities if needed.",
			})
		}

		if c.RunAsRoot {
			out = append(out, Finding{
				ID:       "kube_run_as_root",
				Severity: SeverityHigh,
				Title:    fmt.Sprintf("Container %q in %s %q runs as root", c.Name, m.Kind, m.Name),
				File:     m.Path,
				Line:     c.RunAsRootLine,
				Evidence: fmt.Sprintf("container=%s runAsUser=0 or runAsNonRoot=false", c.Name),
				Why:      "Running as root inside the container increases the blast radius of any container escape. AI workloads should run as a non-root user.",
				Fix:      "Set securityContext.runAsNonRoot: true and runAsUser to a non-zero UID.",
			})
		}

		for _, hp := range c.HostPathMounts {
			sev := SeverityHigh
			if hp.ReadOnly {
				sev = SeverityMedium
			}
			if isSensitiveHostPath(hp.HostPath) {
				sev = SeverityCritical
			}
			out = append(out, Finding{
				ID:       "kube_host_path",
				Severity: sev,
				Title:    fmt.Sprintf("Container %q mounts host path %q", c.Name, hp.HostPath),
				File:     m.Path,
				Line:     hp.Line,
				Evidence: fmt.Sprintf("hostPath=%s mountPath=%s readOnly=%v", hp.HostPath, hp.MountPath, hp.ReadOnly),
				Why:      "Host path mounts give the container direct access to host filesystem paths. Sensitive paths like /var/run/docker.sock or /etc can lead to full host compromise.",
				Fix:      "Use emptyDir, PVC or configMap instead. If host access is necessary, mount read-only and restrict to the minimum path.",
			})
		}
	}
	return out
}

func kubeHostNetworkFindings(m collect.KubeManifest) []Finding {
	if !m.HostNetwork {
		return nil
	}
	return []Finding{{
		ID:       "kube_host_network",
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("%s %q uses hostNetwork", m.Kind, m.Name),
		File:     m.Path,
		Line:     m.HostNetworkLine,
		Evidence: fmt.Sprintf("kind=%s name=%s hostNetwork=true", m.Kind, m.Name),
		Why:      "hostNetwork: true puts the pod on the host's network stack, making every listening port reachable from the host network without any Service or ingress.",
		Fix:      "Remove hostNetwork or set it to false. Use a Service with NetworkPolicy for controlled access.",
	}}
}

func helmFindings(values []collect.HelmValues) []Finding {
	var out []Finding
	for _, hv := range values {
		for _, f := range hv.Findings {
			sev, title := helmFindingSeverityAndTitle(f.KeyPath, f.Value)
			out = append(out, Finding{
				ID:       "helm_insecure_default",
				Severity: sev,
				Title:    title,
				File:     hv.Path,
				Line:     f.Line,
				Evidence: fmt.Sprintf("%s=%s", f.KeyPath, f.Value),
				Why:      "Helm values.yaml sets defaults used when the chart is installed without overrides. An insecure default means every install that doesn't explicitly tighten it ships vulnerable.",
				Fix:      "Change the default in values.yaml to the secure value, or document that the deployer must override it.",
			})
		}
	}
	return out
}

func helmFindingSeverityAndTitle(keyPath, value string) (Severity, string) {
	lower := strings.ToLower(keyPath)
	switch {
	case strings.Contains(lower, "privileged"):
		return SeverityCritical, fmt.Sprintf("Helm default %s=%s (privileged container)", keyPath, value)
	case strings.Contains(lower, "hostnetwork"):
		return SeverityHigh, fmt.Sprintf("Helm default %s=%s (host network)", keyPath, value)
	case strings.Contains(lower, "runasuser") && value == "0":
		return SeverityHigh, fmt.Sprintf("Helm default %s=%s (runs as root)", keyPath, value)
	case strings.Contains(lower, "runasnonroot"):
		return SeverityHigh, fmt.Sprintf("Helm default %s=%s (allows root)", keyPath, value)
	case strings.Contains(lower, "service") && strings.Contains(lower, "type"):
		return SeverityHigh, fmt.Sprintf("Helm default %s=%s (external service)", keyPath, value)
	case strings.Contains(lower, "hostpath"):
		return SeverityHigh, fmt.Sprintf("Helm default %s=%s (host path mount)", keyPath, value)
	default:
		return SeverityMedium, fmt.Sprintf("Helm insecure default %s=%s", keyPath, value)
	}
}

func isSensitiveHostPath(path string) bool {
	sensitive := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/containerd",
		"/etc",
		"/root",
		"/proc",
		"/sys",
	}
	for _, s := range sensitive {
		if path == s || strings.HasPrefix(path, s+"/") {
			return true
		}
	}
	return false
}
