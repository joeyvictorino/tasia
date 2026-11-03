package xmlinjection

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
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	XMLParserExposures  int `json:"xml_parser_exposures"`
	XXEVectors          int `json:"xxe_vectors"`
	DTDProcessing       int `json:"dtd_processing"`
	XPathInjections     int `json:"xpath_injections"`
	EntityExpansion     int `json:"entity_expansion"`
	UnsafeDeserialization int `json:"unsafe_deserialization"`
}

var xmlParserEnvVars = []string{
	"XML_PARSER",
	"LIBXML_PARSER",
	"SAX_PARSER",
	"DOM_PARSER",
	"XML_CATALOG",
	"XMLLINT",
}

var xxeIndicators = []string{
	"<!entity",
	"<!doctype",
	"system \"file:",
	"system \"http:",
	"public \"",
	"<!attlist",
}

var dtdIndicators = []string{
	".dtd",
	"dtd_validation",
	"validate_dtd",
	"load_dtd",
	"external_dtd",
	"dtd_processing",
}

var xpathIndicators = []string{
	"xpath",
	"xml_query",
	"xquery",
	"xmldb",
	"xml_search",
}

var entityExpansionIndicators = []string{
	"billion_laughs",
	"entity_expansion",
	"recursive_entity",
	"xml_bomb",
	"exponential_entity",
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
		key := strings.ToUpper(parts[0])
		val := parts[1]

		for _, xmlVar := range xmlParserEnvVars {
			if strings.Contains(key, xmlVar) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "xml_parser_exposure",
					Message: fmt.Sprintf("Service '%s' sets XML parser config via env '%s'; ensure external entity processing is disabled", svc.Name, parts[0]),
				})
			}
		}

		if containsAny(val, xxeIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "xxe_vector",
				Message: fmt.Sprintf("Service '%s' env '%s' contains XXE-related content: '%s'", svc.Name, parts[0], val),
			})
		}

		if containsAny(val, dtdIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "dtd_processing",
				Message: fmt.Sprintf("Service '%s' env '%s' references DTD processing: '%s'", svc.Name, parts[0], val),
			})
		}

		if containsAny(val, xpathIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "xpath_injection",
				Message: fmt.Sprintf("Service '%s' env '%s' references XPath query capabilities: '%s'", svc.Name, parts[0], val),
			})
		}

		if containsAny(val, entityExpansionIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "entity_expansion",
				Message: fmt.Sprintf("Service '%s' env '%s' references entity expansion patterns: '%s'", svc.Name, parts[0], val),
			})
		}
	}

	for _, v := range svc.Volumes {
		vLower := strings.ToLower(v)
		if strings.Contains(vLower, ".dtd") || strings.Contains(vLower, "/dtd/") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "dtd_processing",
				Message: fmt.Sprintf("Service '%s' mounts DTD-related path: '%s'", svc.Name, v),
			})
		}
		if strings.Contains(vLower, "xml_catalog") || strings.Contains(vLower, "xmlcatalog") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "xml_parser_exposure",
				Message: fmt.Sprintf("Service '%s' mounts XML catalog path: '%s'", svc.Name, v),
			})
		}
	}

	for _, cmd := range svc.Command {
		if containsAny(cmd, xxeIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "xxe_vector",
				Message: fmt.Sprintf("Service '%s' command references XXE patterns: '%s'", svc.Name, cmd),
			})
		}
		if containsAny(cmd, xpathIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "xpath_injection",
				Message: fmt.Sprintf("Service '%s' command references XPath: '%s'", svc.Name, cmd),
			})
		}
	}

	for _, ep := range svc.Entrypoint {
		if containsAny(ep, xxeIndicators) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "xxe_vector",
				Message: fmt.Sprintf("Service '%s' entrypoint references XXE patterns: '%s'", svc.Name, ep),
			})
		}
	}

	for _, port := range svc.Ports {
		portLower := strings.ToLower(port.Raw)
		if strings.Contains(portLower, "8080") || strings.Contains(portLower, "8443") {
			if containsAny(svc.Image, []string{"xml", "soap", "wsdl"}) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "xml_parser_exposure",
					Message: fmt.Sprintf("Service '%s' exposes web port '%s' with XML-related image '%s'", svc.Name, port.Raw, svc.Image),
				})
			}
		}
	}

	if containsAny(svc.Image, []string{"xml", "soap", "wsdl", "xslt"}) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "xml_parser_exposure",
			Message: fmt.Sprintf("Service '%s' uses XML-related image '%s'; verify external entity processing is disabled", svc.Name, svc.Image),
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
			case "xml_parser_exposure":
				s.XMLParserExposures++
			case "xxe_vector":
				s.XXEVectors++
			case "dtd_processing":
				s.DTDProcessing++
			case "xpath_injection":
				s.XPathInjections++
			case "entity_expansion":
				s.EntityExpansion++
			case "unsafe_deserialization":
				s.UnsafeDeserialization++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "XML Injection Risk Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  XML parser exposures:       %d\n", r.Summary.XMLParserExposures)
	fmt.Fprintf(&b, "  XXE vectors:                %d\n", r.Summary.XXEVectors)
	fmt.Fprintf(&b, "  DTD processing:             %d\n", r.Summary.DTDProcessing)
	fmt.Fprintf(&b, "  XPath injections:           %d\n", r.Summary.XPathInjections)
	fmt.Fprintf(&b, "  Entity expansion:           %d\n", r.Summary.EntityExpansion)
	fmt.Fprintf(&b, "  Unsafe deserialization:      %d\n\n", r.Summary.UnsafeDeserialization)
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
