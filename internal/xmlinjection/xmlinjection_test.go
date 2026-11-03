package xmlinjection

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func findRule(r Report, rule string) *Finding {
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return &f
			}
		}
	}
	return nil
}

func countRule(r Report, rule string) int {
	count := 0
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				count++
			}
		}
	}
	return count
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestCleanService(t *testing.T) {
	s := svc("web")
	s.Environment = []string{"APP_PORT=8080"}
	c := mkCollected(s)
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestXMLParserEnvExposure(t *testing.T) {
	s := svc("parser")
	s.Environment = []string{"XML_PARSER=libxml2"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xml_parser_exposure") == nil {
		t.Fatal("expected xml_parser_exposure finding")
	}
}

func TestSAXParserEnv(t *testing.T) {
	s := svc("sax")
	s.Environment = []string{"SAX_PARSER=expat"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xml_parser_exposure") == nil {
		t.Fatal("expected xml_parser_exposure for SAX_PARSER")
	}
}

func TestDOMParserEnv(t *testing.T) {
	s := svc("dom")
	s.Environment = []string{"DOM_PARSER=xerces"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xml_parser_exposure") == nil {
		t.Fatal("expected xml_parser_exposure for DOM_PARSER")
	}
}

func TestXXEVectorInEnvValue(t *testing.T) {
	s := svc("xxe")
	s.Environment = []string{"CONFIG=<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xxe_vector") == nil {
		t.Fatal("expected xxe_vector finding for entity declaration")
	}
}

func TestXXEDoctypeInEnv(t *testing.T) {
	s := svc("doctype")
	s.Environment = []string{"XML_TEMPLATE=<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil\">]>"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xxe_vector") == nil {
		t.Fatal("expected xxe_vector for DOCTYPE")
	}
}

func TestDTDProcessingEnvValue(t *testing.T) {
	s := svc("dtd")
	s.Environment = []string{"SCHEMA_PATH=/opt/schemas/config.dtd"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "dtd_processing") == nil {
		t.Fatal("expected dtd_processing for .dtd reference")
	}
}

func TestDTDValidationEnv(t *testing.T) {
	s := svc("validate")
	s.Environment = []string{"XML_OPTIONS=dtd_validation=true"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "dtd_processing") == nil {
		t.Fatal("expected dtd_processing for dtd_validation")
	}
}

func TestXPathInjectionEnv(t *testing.T) {
	s := svc("xpath")
	s.Environment = []string{"QUERY_ENGINE=xpath"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xpath_injection") == nil {
		t.Fatal("expected xpath_injection for xpath reference")
	}
}

func TestXQueryEnv(t *testing.T) {
	s := svc("xquery")
	s.Environment = []string{"DB_QUERY=xquery"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xpath_injection") == nil {
		t.Fatal("expected xpath_injection for xquery")
	}
}

func TestEntityExpansionEnv(t *testing.T) {
	s := svc("bomb")
	s.Environment = []string{"ATTACK_TYPE=billion_laughs"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "entity_expansion") == nil {
		t.Fatal("expected entity_expansion for billion_laughs")
	}
}

func TestEntityExpansionXMLBomb(t *testing.T) {
	s := svc("xmlbomb")
	s.Environment = []string{"TEST_PAYLOAD=xml_bomb"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "entity_expansion") == nil {
		t.Fatal("expected entity_expansion for xml_bomb")
	}
}

func TestDTDVolumeMount(t *testing.T) {
	s := svc("dtd-vol")
	s.Volumes = []string{"/schemas/app.dtd:/app/schema.dtd"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "dtd_processing") == nil {
		t.Fatal("expected dtd_processing for DTD volume mount")
	}
}

func TestDTDDirectoryMount(t *testing.T) {
	s := svc("dtd-dir")
	s.Volumes = []string{"/opt/dtd/:/app/dtd/"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "dtd_processing") == nil {
		t.Fatal("expected dtd_processing for /dtd/ directory mount")
	}
}

func TestXMLCatalogVolumeMount(t *testing.T) {
	s := svc("catalog")
	s.Volumes = []string{"/etc/xml_catalog:/app/catalog"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xml_parser_exposure") == nil {
		t.Fatal("expected xml_parser_exposure for xml_catalog mount")
	}
}

func TestXXEInCommand(t *testing.T) {
	s := svc("cmd-xxe")
	s.Command = []string{"xmllint", "--noent", "<!DOCTYPE foo>"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xxe_vector") == nil {
		t.Fatal("expected xxe_vector for DOCTYPE in command")
	}
}

func TestXPathInCommand(t *testing.T) {
	s := svc("cmd-xpath")
	s.Command = []string{"xmlstarlet", "sel", "-t", "-v", "xpath expression"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xpath_injection") == nil {
		t.Fatal("expected xpath_injection for xpath in command")
	}
}

func TestXXEInEntrypoint(t *testing.T) {
	s := svc("ep-xxe")
	s.Entrypoint = []string{"sh", "-c", "echo '<!ENTITY foo SYSTEM \"file:///etc/shadow\">'"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xxe_vector") == nil {
		t.Fatal("expected xxe_vector for entity in entrypoint")
	}
}

func TestXMLRelatedImage(t *testing.T) {
	s := svc("soap-svc")
	s.Image = "company/soap-gateway:latest"
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xml_parser_exposure") == nil {
		t.Fatal("expected xml_parser_exposure for SOAP image")
	}
}

func TestWSDLImage(t *testing.T) {
	s := svc("wsdl-svc")
	s.Image = "wsdl-processor:v2"
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xml_parser_exposure") == nil {
		t.Fatal("expected xml_parser_exposure for WSDL image")
	}
}

func TestXSLTImage(t *testing.T) {
	s := svc("xslt-svc")
	s.Image = "xslt-engine:1.0"
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xml_parser_exposure") == nil {
		t.Fatal("expected xml_parser_exposure for XSLT image")
	}
}

func TestNormalImageNoFinding(t *testing.T) {
	s := svc("web")
	s.Image = "nginx:latest"
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "xml_parser_exposure") != nil {
		t.Fatal("nginx should not trigger xml_parser_exposure")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("complex")
	s.Environment = []string{"XML_PARSER=expat", "SCHEMA=config.dtd", "QUERY=xpath"}
	c := mkCollected(s)
	r := Analyze(c)
	if r.Summary.XMLParserExposures < 1 {
		t.Fatal("expected XMLParserExposures > 0")
	}
	if r.Summary.TotalFindings < 3 {
		t.Fatalf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if !strings.Contains(text, "0 findings") {
		t.Fatal("expected 0 findings in output")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("xxe-svc")
	s.Environment = []string{"CONFIG=<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"}
	c := mkCollected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "xxe-svc") {
		t.Fatal("expected service name in text output")
	}
	if !strings.Contains(text, "XML Injection") {
		t.Fatal("expected header in text output")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/project"}
	r := Analyze(c)
	if r.Path != "/project" {
		t.Fatalf("expected /project, got %s", r.Path)
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("a")
	s2 := svc("b")
	c := mkCollected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}
