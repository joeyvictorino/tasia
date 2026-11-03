package deserializationaudit

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

func TestPickleInEnv(t *testing.T) {
	s := svc("ml")
	s.Environment = []string{"MODEL_FORMAT=pickle"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_pickle") == nil {
		t.Fatal("expected unsafe_pickle for pickle env")
	}
}

func TestCPickleInEnv(t *testing.T) {
	s := svc("ml2")
	s.Environment = []string{"SERIALIZER=cpickle"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_pickle") == nil {
		t.Fatal("expected unsafe_pickle for cpickle")
	}
}

func TestCloudpickleEnv(t *testing.T) {
	s := svc("spark")
	s.Environment = []string{"SERIALIZER=cloudpickle"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_pickle") == nil {
		t.Fatal("expected unsafe_pickle for cloudpickle")
	}
}

func TestJavaDeserializationEnv(t *testing.T) {
	s := svc("java")
	s.Environment = []string{"STREAM_CLASS=ObjectInputStream"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "java_deserialization") == nil {
		t.Fatal("expected java_deserialization for ObjectInputStream")
	}
}

func TestYsoserialEnv(t *testing.T) {
	s := svc("exploit")
	s.Environment = []string{"TOOL=ysoserial"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "java_deserialization") == nil {
		t.Fatal("expected java_deserialization for ysoserial")
	}
}

func TestYAMLUnsafeLoadEnv(t *testing.T) {
	s := svc("config")
	s.Environment = []string{"LOADER=yaml.unsafe_load"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "yaml_loading") == nil {
		t.Fatal("expected yaml_loading for yaml.unsafe_load")
	}
}

func TestYAMLLoadEnv(t *testing.T) {
	s := svc("parser")
	s.Environment = []string{"PARSE_METHOD=yaml.load"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "yaml_loading") == nil {
		t.Fatal("expected yaml_loading for yaml.load")
	}
}

func TestPHPUnserializeEnv(t *testing.T) {
	s := svc("php")
	s.Environment = []string{"HANDLER=unserialize"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "php_unserialize") == nil {
		t.Fatal("expected php_unserialize for unserialize")
	}
}

func TestPHPPharEnv(t *testing.T) {
	s := svc("phar")
	s.Environment = []string{"INCLUDE_PATH=phar://app.phar"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "php_unserialize") == nil {
		t.Fatal("expected php_unserialize for phar://")
	}
}

func TestMarshalVulnEnv(t *testing.T) {
	s := svc("dotnet")
	s.Environment = []string{"FORMATTER=BinaryFormatter"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "marshal_vulnerability") == nil {
		t.Fatal("expected marshal_vulnerability for BinaryFormatter")
	}
}

func TestProtobufRiskEnv(t *testing.T) {
	s := svc("grpc")
	s.Environment = []string{"DECODER=msgpack_unpack"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "protobuf_risk") == nil {
		t.Fatal("expected protobuf_risk for msgpack_unpack")
	}
}

func TestPickleInCommand(t *testing.T) {
	s := svc("cmd-pkl")
	s.Command = []string{"python", "-c", "import pickle; pickle.loads(data)"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_pickle") == nil {
		t.Fatal("expected unsafe_pickle for pickle in command")
	}
}

func TestJavaDeserInCommand(t *testing.T) {
	s := svc("cmd-java")
	s.Command = []string{"java", "-cp", "app.jar", "ObjectInputStream"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "java_deserialization") == nil {
		t.Fatal("expected java_deserialization in command")
	}
}

func TestYAMLInCommand(t *testing.T) {
	s := svc("cmd-yaml")
	s.Command = []string{"python", "-c", "yaml.load(open('config.yml'))"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "yaml_loading") == nil {
		t.Fatal("expected yaml_loading in command")
	}
}

func TestPickleInEntrypoint(t *testing.T) {
	s := svc("ep-pkl")
	s.Entrypoint = []string{"python", "unpickle_model.py"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_pickle") == nil {
		t.Fatal("expected unsafe_pickle for unpickle in entrypoint")
	}
}

func TestPHPInEntrypoint(t *testing.T) {
	s := svc("ep-php")
	s.Entrypoint = []string{"php", "-r", "unserialize($input)"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "php_unserialize") == nil {
		t.Fatal("expected php_unserialize in entrypoint")
	}
}

func TestPickleVolumeMount(t *testing.T) {
	s := svc("vol-pkl")
	s.Volumes = []string{"/models/model.pkl:/app/model.pkl"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_pickle") == nil {
		t.Fatal("expected unsafe_pickle for .pkl volume mount")
	}
}

func TestSerializedVolumeMount(t *testing.T) {
	s := svc("vol-ser")
	s.Volumes = []string{"/data/cache.ser:/app/cache.ser"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "java_deserialization") == nil {
		t.Fatal("expected java_deserialization for .ser volume mount")
	}
}

func TestDeserializationImage(t *testing.T) {
	s := svc("deser-img")
	s.Image = "custom/ysoserial-runner:latest"
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "java_deserialization") == nil {
		t.Fatal("expected java_deserialization for ysoserial image")
	}
}

func TestNormalImageNoFinding(t *testing.T) {
	s := svc("web")
	s.Image = "nginx:latest"
	c := mkCollected(s)
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for nginx, got %d", r.Summary.TotalFindings)
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("multi")
	s.Environment = []string{"A=pickle", "B=ObjectInputStream", "C=yaml.load"}
	c := mkCollected(s)
	r := Analyze(c)
	if r.Summary.UnsafePickle < 1 {
		t.Fatal("expected UnsafePickle > 0")
	}
	if r.Summary.JavaDeserialization < 1 {
		t.Fatal("expected JavaDeserialization > 0")
	}
	if r.Summary.YAMLLoading < 1 {
		t.Fatal("expected YAMLLoading > 0")
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
	s := svc("pkl-svc")
	s.Environment = []string{"MODEL_FORMAT=pickle"}
	c := mkCollected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "pkl-svc") {
		t.Fatal("expected service name in text output")
	}
	if !strings.Contains(text, "Deserialization") {
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
