package deserializationaudit

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type ServiceResult struct {
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices        int `json:"total_services"`
	TotalFindings        int `json:"total_findings"`
	UnsafePickle         int `json:"unsafe_pickle"`
	JavaDeserialization   int `json:"java_deserialization"`
	YAMLLoading          int `json:"yaml_loading"`
	PHPUnserialize       int `json:"php_unserialize"`
	MarshalVulnerability int `json:"marshal_vulnerability"`
	ProtobufRisks        int `json:"protobuf_risks"`
}

var pickleIndicators = []string{
	"pickle", "cpickle", "unpickle", "pickle.loads",
	"shelve", "dill", "cloudpickle",
}

var javaDeserialIndicators = []string{
	"objectinputstream", "java_deserialization", "readobject",
	"writeobject", "java.io.serializable", "ysoserial",
	"commons-collections", "gadget_chain", "rmi_registry",
}

var yamlLoadIndicators = []string{
	"yaml.load", "yaml.unsafe_load", "yaml.full_load",
	"yaml_unsafe", "ruamel.yaml", "pyyaml",
}

var phpUnserializeIndicators = []string{
	"unserialize", "php_serialize", "php_deserialization",
	"__wakeup", "__destruct", "phar://",
}

var marshalIndicators = []string{
	"marshal.loads", "marshal_unsafe", "ruby_marshal",
	"dotnet_binaryformatter", "binaryformatter",
	"netdatacontractserializer", "xmlserializer",
}

var protobufRiskIndicators = []string{
	"protobuf_unsafe", "grpc_deserialize", "proto_decode",
	"msgpack_unpack", "avro_deserialize", "thrift_deserialize",
}

func containsAny(s string, indicators []string) bool {
	lower := strings.ToLower(s)
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) < 2 {
			continue
		}
		val := parts[1]
		key := parts[0]

		if containsAny(val, pickleIndicators) || containsAny(key, pickleIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "unsafe_pickle",
				Message: fmt.Sprintf("Service '%s' env '%s' references Python pickle deserialization; pickle.loads() executes arbitrary code", svc.Name, key),
			})
		}

		if containsAny(val, javaDeserialIndicators) || containsAny(key, javaDeserialIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "java_deserialization",
				Message: fmt.Sprintf("Service '%s' env '%s' references Java deserialization; ObjectInputStream is a known RCE vector", svc.Name, key),
			})
		}

		if containsAny(val, yamlLoadIndicators) || containsAny(key, yamlLoadIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "yaml_loading",
				Message: fmt.Sprintf("Service '%s' env '%s' references unsafe YAML loading; use yaml.safe_load() instead", svc.Name, key),
			})
		}

		if containsAny(val, phpUnserializeIndicators) || containsAny(key, phpUnserializeIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "php_unserialize",
				Message: fmt.Sprintf("Service '%s' env '%s' references PHP unserialize; this enables object injection attacks", svc.Name, key),
			})
		}

		if containsAny(val, marshalIndicators) || containsAny(key, marshalIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "marshal_vulnerability",
				Message: fmt.Sprintf("Service '%s' env '%s' references unsafe marshal/binary deserialization", svc.Name, key),
			})
		}

		if containsAny(val, protobufRiskIndicators) || containsAny(key, protobufRiskIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "protobuf_risk",
				Message: fmt.Sprintf("Service '%s' env '%s' references binary protocol deserialization; validate input schemas", svc.Name, key),
			})
		}
	}

	for _, cmd := range svc.Command {
		if containsAny(cmd, pickleIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "unsafe_pickle",
				Message: fmt.Sprintf("Service '%s' command references pickle: '%s'", svc.Name, cmd),
			})
		}
		if containsAny(cmd, javaDeserialIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "java_deserialization",
				Message: fmt.Sprintf("Service '%s' command references Java deserialization: '%s'", svc.Name, cmd),
			})
		}
		if containsAny(cmd, yamlLoadIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "yaml_loading",
				Message: fmt.Sprintf("Service '%s' command references unsafe YAML loading: '%s'", svc.Name, cmd),
			})
		}
	}

	for _, ep := range svc.Entrypoint {
		if containsAny(ep, pickleIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "unsafe_pickle",
				Message: fmt.Sprintf("Service '%s' entrypoint references pickle: '%s'", svc.Name, ep),
			})
		}
		if containsAny(ep, phpUnserializeIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "php_unserialize",
				Message: fmt.Sprintf("Service '%s' entrypoint references PHP unserialize: '%s'", svc.Name, ep),
			})
		}
	}

	for _, v := range svc.Volumes {
		vLower := strings.ToLower(v)
		if strings.Contains(vLower, "pickle") || strings.Contains(vLower, ".pkl") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "unsafe_pickle",
				Message: fmt.Sprintf("Service '%s' mounts pickle-related path: '%s'", svc.Name, v),
			})
		}
		if strings.Contains(vLower, "serialized") || strings.Contains(vLower, ".ser") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "java_deserialization",
				Message: fmt.Sprintf("Service '%s' mounts serialized data path: '%s'", svc.Name, v),
			})
		}
	}

	imgLower := strings.ToLower(svc.Image)
	if strings.Contains(imgLower, "ysoserial") || strings.Contains(imgLower, "deserialize") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "java_deserialization",
			Message: fmt.Sprintf("Service '%s' uses deserialization-related image '%s'", svc.Name, svc.Image),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "unsafe_pickle":
				s.UnsafePickle++
			case "java_deserialization":
				s.JavaDeserialization++
			case "yaml_loading":
				s.YAMLLoading++
			case "php_unserialize":
				s.PHPUnserialize++
			case "marshal_vulnerability":
				s.MarshalVulnerability++
			case "protobuf_risk":
				s.ProtobufRisks++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Deserialization Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Unsafe pickle:              %d\n", r.Summary.UnsafePickle)
	fmt.Fprintf(&b, "  Java deserialization:        %d\n", r.Summary.JavaDeserialization)
	fmt.Fprintf(&b, "  YAML loading:               %d\n", r.Summary.YAMLLoading)
	fmt.Fprintf(&b, "  PHP unserialize:             %d\n", r.Summary.PHPUnserialize)
	fmt.Fprintf(&b, "  Marshal vulnerability:       %d\n", r.Summary.MarshalVulnerability)
	fmt.Fprintf(&b, "  Protobuf risks:              %d\n\n", r.Summary.ProtobufRisks)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
