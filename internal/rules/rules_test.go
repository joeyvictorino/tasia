package rules

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestEvaluateExposedAndLatest(t *testing.T) {
	c := &collect.Collected{
		Root: "/tmp/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:      "ollama",
						Image:     "ollama/ollama:latest",
						ImageLine: 3,
						Ports:     []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434:11434", Line: 5}},
					},
					{
						Name:  "webui",
						Image: "ghcr.io/open-webui/open-webui:latest",
						Ports: []compose.PortMapping{{HostPort: 3000, TargetPort: 8080, Raw: "3000:8080", Line: 10}},
					},
				},
			},
		},
	}
	fs := Evaluate(c)
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	hasExposed := false
	hasLatest := false
	for _, f := range fs {
		if f.ID == "exposed_inference" && f.Severity == "HIGH" && f.Line == 5 {
			hasExposed = true
		}
		if f.ID == "latest_image" {
			hasLatest = true
		}
	}
	if !hasExposed {
		t.Error("missing HIGH exposed_inference finding with line")
	}
	if !hasLatest {
		t.Error("missing latest image finding")
	}
}

func TestPermissiveCORSAndComposeEnvKeys(t *testing.T) {
	c := &collect.Collected{
		Root: "/tmp/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "ollama",
						Image:       "ollama/ollama:0.3",
						Ports:       []compose.PortMapping{{HostPort: 11434, Raw: "11434:11434", Line: 5}},
						Environment: []string{"OLLAMA_ORIGINS=*", "HF_TOKEN=hf_xxx"},
					},
				},
			},
		},
	}
	fs := Evaluate(c)
	hasCORS := false
	hasEnvKey := false
	for _, f := range fs {
		if f.ID == "permissive_cors" && f.Severity == "HIGH" {
			hasCORS = true
		}
		if f.ID == "env_token_key" && strings.Contains(f.Evidence, "HF_TOKEN") {
			hasEnvKey = true
		}
	}
	if !hasCORS {
		t.Error("missing HIGH permissive_cors finding for OLLAMA_ORIGINS=*")
	}
	if !hasEnvKey {
		t.Error("missing env token key from compose environment")
	}
}

func TestEnvKeyLineNumbers(t *testing.T) {
	c := &collect.Collected{
		Root:     ".",
		EnvFiles: []collect.EnvFile{{Path: ".env", Keys: []collect.EnvKey{{Name: "OPENAI_API_KEY", Line: 2}, {Name: "HF_TOKEN", Line: 5}}}},
	}
	fs := Evaluate(c)
	want := map[string]int{"OPENAI_API_KEY": 2, "HF_TOKEN": 5}
	got := map[string]int{}
	for _, f := range fs {
		if f.ID == "env_token_key" {
			got[f.Evidence] = f.Line
		}
	}
	for k, ln := range want {
		if got[k] != ln {
			t.Errorf("env_token_key %s: got line %d, want %d", k, got[k], ln)
		}
	}
}

func TestNewComponentDetection(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				// llama.cpp inference by image name, exposed to all interfaces
				{Name: "llamacpp", Image: "ghcr.io/ggerganov/llama.cpp:server", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 8080, Raw: "8080:8080", Line: 3}}},
				// LM Studio by port 1234 with an unknown image
				{Name: "lmstudio", Image: "someone/lmstudio-headless:1.0", Ports: []compose.PortMapping{{HostPort: 1234, TargetPort: 1234, Raw: "1234:1234", Line: 6}}},
				// Weaviate vector DB
				{Name: "weaviate", Image: "semitechnologies/weaviate:1.25", Ports: []compose.PortMapping{{HostPort: 8081, TargetPort: 8080, Raw: "8081:8080", Line: 9}}},
				// Milvus vector DB on 19530
				{Name: "milvus", Image: "milvusdb/milvus:v2.4", Ports: []compose.PortMapping{{HostPort: 19530, TargetPort: 19530, Raw: "19530:19530", Line: 12}}},
			},
		}},
	}
	fs := Evaluate(c)
	// two inference exposures (llama.cpp + LM Studio) and two vector (weaviate + milvus)
	infCount, vecCount := 0, 0
	for _, f := range fs {
		// per-service exposure findings must carry a real line number
		if f.ID == "exposed_inference" || f.ID == "exposed_vector" {
			if f.Line == 0 {
				t.Errorf("finding %s has no line number: %+v", f.ID, f)
			}
		}
		if f.ID == "exposed_inference" {
			infCount++
		}
		if f.ID == "exposed_vector" {
			vecCount++
		}
	}
	if infCount != 2 {
		t.Errorf("expected 2 exposed_inference (llama.cpp + LM Studio), got %d", infCount)
	}
	if vecCount != 2 {
		t.Errorf("expected 2 exposed_vector (weaviate + milvus), got %d", vecCount)
	}
}

func TestDatastoreExposureSeverity(t *testing.T) {
	// Redis alongside AI (ollama) => HIGH
	withAI := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "ollama", Image: "ollama/ollama:0.3", Ports: []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434:11434", Line: 3}}},
				{Name: "redis", Image: "redis:7", Ports: []compose.PortMapping{{HostPort: 6379, TargetPort: 6379, Raw: "6379:6379", Line: 6}}},
			},
		}},
	}
	var redisSev Severity
	for _, f := range Evaluate(withAI) {
		if f.ID == "exposed_datastore" {
			redisSev = f.Severity
			if f.Line != 6 {
				t.Errorf("redis datastore finding line: got %d want 6", f.Line)
			}
		}
	}
	if redisSev != SeverityHigh {
		t.Errorf("redis alongside AI should be HIGH, got %q", redisSev)
	}

	// Postgres with no AI component => MEDIUM
	noAI := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "db", Image: "postgres:16", Ports: []compose.PortMapping{{HostPort: 5432, TargetPort: 5432, Raw: "5432:5432", Line: 3}}},
				{Name: "app", Image: "myorg/app:1.2", Ports: []compose.PortMapping{{HostPort: 9000, TargetPort: 9000, Raw: "9000:9000", Line: 6}}},
			},
		}},
	}
	var pgSev Severity
	for _, f := range Evaluate(noAI) {
		if f.ID == "exposed_datastore" {
			pgSev = f.Severity
		}
	}
	if pgSev != SeverityMedium {
		t.Errorf("postgres with no AI component should be MEDIUM, got %q", pgSev)
	}
}

func TestNetworkModeHostExposure(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "ollama", Image: "ollama/ollama:0.3", NetworkMode: "host", NetworkModeLine: 4},
			},
		}},
	}
	var found *Finding
	for _, f := range Evaluate(c) {
		if f.ID == "exposed_inference" {
			ff := f
			found = &ff
		}
	}
	if found == nil {
		t.Fatal("network_mode: host inference exposure not detected")
	}
	if found.Severity != SeverityHigh || found.Line != 4 || !strings.Contains(found.Evidence, "network_mode: host") {
		t.Errorf("bad host-network finding: %+v", *found)
	}
}

func TestHostIPLocalhostNotFlagged(t *testing.T) {
	// Long-form port explicitly bound to 127.0.0.1 must NOT be an exposure.
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "ollama", Image: "ollama/ollama:0.3",
					Ports: []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434", HostIP: "127.0.0.1", Line: 5}}},
			},
		}},
	}
	for _, f := range Evaluate(c) {
		if f.ID == "exposed_inference" {
			t.Errorf("localhost-bound (host_ip 127.0.0.1) port must not be flagged: %+v", f)
		}
	}
}

func TestLongFormDockerSocket(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "ui", Image: "portainer/portainer:2.0", VolumesLine: 4,
					Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"}},
			},
		}},
	}
	found := false
	for _, f := range Evaluate(c) {
		if f.ID == "docker_socket_mount" && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("docker.sock mount (long-form) not detected")
	}
}

func TestNoSecretValues(t *testing.T) {
	// ensure rule never invents values; here just env keys
	c := &collect.Collected{
		Root:         ".",
		EnvFiles:     []collect.EnvFile{{Path: ".env", Keys: []collect.EnvKey{{Name: "HF_TOKEN", Line: 1}, {Name: "OPENAI_API_KEY", Line: 2}}}},
		ComposeFiles: []compose.File{{Path: "c.yml", Services: []compose.Service{{Name: "x", Image: "ollama/ollama:0.1"}}}},
	}
	fs := Evaluate(c)
	for _, f := range fs {
		if containsAny(f.Evidence, []string{"sk-", "hf_", "realvalue"}) || strings.Contains(f.Why, "sk-") {
			t.Errorf("possible secret leak in finding: %+v", f)
		}
	}
}

func TestLatestImageEdgeCases(t *testing.T) {
	mk := func(img string) *collect.Collected {
		return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml",
			Services: []compose.Service{{Name: "s", Image: img, ImageLine: 3}}}}}
	}
	flagged := func(img string) bool {
		for _, f := range Evaluate(mk(img)) {
			if f.ID == "latest_image" {
				return true
			}
		}
		return false
	}
	if !flagged("ollama/ollama") {
		t.Error("untagged image should be flagged")
	}
	if !flagged("myreg:5000/ollama") {
		t.Error("untagged image behind registry:port should be flagged")
	}
	if flagged("myreg:5000/ollama:0.3") {
		t.Error("tagged image behind registry:port should NOT be flagged")
	}
	if flagged("ollama/ollama@sha256:abc123") {
		t.Error("digest-pinned image should NOT be flagged")
	}
}

func TestBroadBindMountReadOnly(t *testing.T) {
	mk := func(vol string) *collect.Collected {
		return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml",
			Services: []compose.Service{{Name: "s", Image: "x:1", VolumesLine: 4, Volumes: []string{vol}}}}}}
	}
	flagged := func(vol string) bool {
		for _, f := range Evaluate(mk(vol)) {
			if f.ID == "broad_bind_mount" {
				return true
			}
		}
		return false
	}
	if !flagged(".:/app") {
		t.Error(".:/app should be flagged")
	}
	if flagged(".:/app:ro") {
		t.Error("read-only .:/app:ro should NOT be flagged")
	}
	if flagged("/data/prometheus:/prometheus") {
		t.Error("unrelated path containing 'ro' substring should NOT be flagged as broad")
	}
}

func TestAgentRuntimeExposure(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				// by image, published to all interfaces
				{Name: "flowise", Image: "flowiseai/flowise:2.1", Ports: []compose.PortMapping{{HostPort: 3001, TargetPort: 3000, Raw: "3001:3000", Line: 3}}},
				// unknown image, well-known n8n port
				{Name: "automation", Image: "internal/automation:1", Ports: []compose.PortMapping{{HostPort: 5678, TargetPort: 5678, Raw: "5678:5678", Line: 6}}},
				// by image, on the host network
				{Name: "langflow", Image: "langflowai/langflow:1.1", NetworkMode: "host", NetworkModeLine: 9},
				// bound to localhost: no exposure finding
				{Name: "n8n", Image: "n8nio/n8n:1.60", Ports: []compose.PortMapping{{HostPort: 5678, TargetPort: 5678, Raw: "127.0.0.1:5678:5678", Line: 12}}},
			},
		}},
	}
	lines := map[int]bool{}
	for _, f := range Evaluate(c) {
		if f.ID != "exposed_agent_runtime" {
			continue
		}
		if f.Severity != SeverityHigh {
			t.Errorf("agent runtime exposure should be HIGH: %+v", f)
		}
		lines[f.Line] = true
	}
	for _, want := range []int{3, 6, 9} {
		if !lines[want] {
			t.Errorf("expected exposed_agent_runtime at line %d, got lines %v", want, lines)
		}
	}
	if lines[12] {
		t.Error("localhost-bound n8n must not be flagged")
	}
	if len(lines) != 3 {
		t.Errorf("expected exactly 3 exposure findings, got %v", lines)
	}
}

func TestAgentRuntimeImageMatching(t *testing.T) {
	cases := map[string]bool{
		"n8nio/n8n:1.60":                      true,
		"docker.n8n.io/n8nio/n8n":             true,
		"n8n":                                 true,
		"flowiseai/flowise":                   true,
		"langflowai/langflow:1.1":             true,
		"langgenius/dify-api:0.9":             true,
		"ghcr.io/all-hands-ai/openhands:0.12": true,
		"ghcr.io/guregodevo/memdoor:1":        true,
		"myorg/autogen-studio:2":              true,
		// near misses that must not classify as agent runtimes
		"myorg/n8n-docs:1":                   false,
		"myorg/autogenerated-api:3":          false,
		"ollama/ollama:0.3":                  false,
		"ghcr.io/open-webui/open-webui:main": false,
	}
	for img, want := range cases {
		_, got := collect.IsAgentRuntimeImage(img)
		if got != want {
			t.Errorf("IsAgentRuntimeImage(%q) = %v, want %v", img, got, want)
		}
		if got && classifyService(img, 0) != catAgent {
			t.Errorf("classifyService(%q) should be catAgent", img)
		}
	}
	// An agent runtime that also serves a UI is judged as an agent runtime.
	if classifyService("langflowai/langflow:1.1", 7860) != catAgent {
		t.Error("langflow on 7860 should classify as an agent runtime, not a UI")
	}
}

func TestBroadBindMountEscalatesOnAgentRuntime(t *testing.T) {
	mk := func(img string) *collect.Collected {
		return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml",
			Services: []compose.Service{{Name: "s", Image: img, VolumesLine: 4, Volumes: []string{".:/data"}}}}}}
	}
	sev := func(img string) Severity {
		for _, f := range Evaluate(mk(img)) {
			if f.ID == "broad_bind_mount" {
				return f.Severity
			}
		}
		return ""
	}
	if got := sev("n8nio/n8n:1.60"); got != SeverityHigh {
		t.Errorf("broad writable mount on an agent runtime should be HIGH, got %q", got)
	}
	if got := sev("myorg/app:1.2"); got != SeverityMedium {
		t.Errorf("broad writable mount on a plain service should stay MEDIUM, got %q", got)
	}
	for _, f := range Evaluate(mk("n8nio/n8n:1.60")) {
		if f.ID == "broad_bind_mount" && !strings.Contains(f.Why, "judge its own work") {
			t.Errorf("agent-runtime why should explain the self-check risk: %q", f.Why)
		}
	}
}

func TestAgentSharedSecrets(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "flowise", Image: "flowiseai/flowise:2.1", EnvLine: 3,
					Environment: []string{"OPENAI_API_KEY=sk-xxx", "FLOWISE_SECRET=abc"}},
				{Name: "n8n", Image: "n8nio/n8n:1.60", EnvLine: 8,
					Environment: []string{"OPENAI_API_KEY=sk-xxx", "N8N_AUTH_TOKEN=tok"}},
				{Name: "redis", Image: "redis:7", EnvLine: 12,
					Environment: []string{"OPENAI_API_KEY=sk-xxx"}},
			},
		}},
	}
	var found []Finding
	for _, f := range Evaluate(c) {
		if f.ID == "agent_shared_secret" {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 agent_shared_secret finding (OPENAI_API_KEY), got %d: %+v", len(found), found)
	}
	if found[0].Severity != SeverityHigh {
		t.Errorf("agent_shared_secret should be HIGH, got %s", found[0].Severity)
	}
	if !strings.Contains(found[0].Evidence, "OPENAI_API_KEY") {
		t.Errorf("evidence should mention the shared key: %s", found[0].Evidence)
	}
	if !strings.Contains(found[0].Evidence, "flowise") || !strings.Contains(found[0].Evidence, "n8n") {
		t.Errorf("evidence should list both agent services: %s", found[0].Evidence)
	}
	// redis is not an agent runtime, so it's excluded from the count
	if strings.Contains(found[0].Evidence, "redis") {
		t.Errorf("non-agent services should not appear in evidence: %s", found[0].Evidence)
	}
}

func TestAgentAutoApproveDetected(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "n8n", Image: "n8nio/n8n:1.60", EnvLine: 3,
					Environment: []string{"N8N_ALLOW_EXEC=true", "N8N_PORT=5678"}},
				{Name: "flowise", Image: "flowiseai/flowise:2.1", EnvLine: 8,
					Environment: []string{"FLOWISE_ALLOW_CODE_EXEC=true", "PORT=3000"}},
				// non-agent service with auto-approve key: should NOT be flagged
				{Name: "app", Image: "myorg/app:1.2", EnvLine: 12,
					Environment: []string{"AUTO_APPROVE=true"}},
			},
		}},
	}
	var found []Finding
	for _, f := range Evaluate(c) {
		if f.ID == "agent_auto_approve" {
			found = append(found, f)
		}
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 agent_auto_approve findings (n8n + flowise), got %d: %+v", len(found), found)
	}
	for _, f := range found {
		if f.Severity != SeverityHigh {
			t.Errorf("agent_auto_approve should be HIGH, got %s", f.Severity)
		}
	}
	// Check evidence doesn't leak values, only key names
	for _, f := range found {
		if strings.Contains(f.Evidence, "true") && !strings.Contains(f.Evidence, "key=") {
			t.Errorf("evidence might contain the value: %s", f.Evidence)
		}
	}
}

func TestAgentAutoApproveNotFlaggedOnNonAgent(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "app", Image: "myorg/app:1.2", EnvLine: 3,
					Environment: []string{"AUTO_APPROVE=true", "ENABLE_CODE_EXECUTION=yes"}},
			},
		}},
	}
	for _, f := range Evaluate(c) {
		if f.ID == "agent_auto_approve" {
			t.Errorf("auto-approve on a non-agent service should not be flagged: %+v", f)
		}
	}
}

func TestVectorDBNoAuthChroma(t *testing.T) {
	// Chroma with no auth env: flagged
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "chroma", Image: "chromadb/chroma:0.5", EnvLine: 3,
					Environment: []string{"CHROMA_DATA_DIR=/data"}},
			},
		}},
	}
	var found []Finding
	for _, f := range Evaluate(c) {
		if f.ID == "vector_db_no_auth" {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 vector_db_no_auth for chroma, got %d", len(found))
	}
	if found[0].Severity != SeverityLow {
		t.Errorf("vector_db_no_auth should be LOW, got %s", found[0].Severity)
	}

	// Chroma WITH auth env: not flagged
	c2 := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "chroma", Image: "chromadb/chroma:0.5", EnvLine: 3,
					Environment: []string{"CHROMA_SERVER_AUTHN_CREDENTIALS=token123"}},
			},
		}},
	}
	for _, f := range Evaluate(c2) {
		if f.ID == "vector_db_no_auth" {
			t.Error("chroma with auth creds should NOT be flagged")
		}
	}
}

func TestVectorDBNoAuthWeaviate(t *testing.T) {
	// Weaviate with no auth
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "weaviate", Image: "semitechnologies/weaviate:1.25", EnvLine: 3,
					Environment: []string{"QUERY_DEFAULTS_LIMIT=20"}},
			},
		}},
	}
	var found bool
	for _, f := range Evaluate(c) {
		if f.ID == "vector_db_no_auth" {
			found = true
		}
	}
	if !found {
		t.Error("weaviate without auth should be flagged")
	}

	// Weaviate WITH apikey auth: not flagged
	c2 := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "weaviate", Image: "semitechnologies/weaviate:1.25", EnvLine: 3,
					Environment: []string{"AUTHENTICATION_APIKEY_ENABLED=true"}},
			},
		}},
	}
	for _, f := range Evaluate(c2) {
		if f.ID == "vector_db_no_auth" {
			t.Error("weaviate with AUTHENTICATION_APIKEY_ENABLED should NOT be flagged")
		}
	}
}

func TestVectorDBNoAuthNotFlaggedOnOther(t *testing.T) {
	// Qdrant and Milvus: should NOT be flagged (no auth keys defined for them)
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "qdrant", Image: "qdrant/qdrant:1.11"},
				{Name: "milvus", Image: "milvusdb/milvus:v2.4"},
			},
		}},
	}
	for _, f := range Evaluate(c) {
		if f.ID == "vector_db_no_auth" {
			t.Errorf("qdrant/milvus should not be flagged by vector_db_no_auth: %+v", f)
		}
	}
}

func TestAgentTestMountDetected(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				// test dir writable on agent: HIGH
				{Name: "n8n", Image: "n8nio/n8n:1.60", VolumesLine: 4,
					Volumes: []string{"./tests:/app/tests", "data:/data"}},
				// fixtures dir writable on agent: HIGH
				{Name: "flowise", Image: "flowiseai/flowise:2.1", VolumesLine: 8,
					Volumes: []string{"./fixtures:/app/fixtures"}},
				// test dir read-only: NOT flagged
				{Name: "langflow", Image: "langflowai/langflow:1.1", VolumesLine: 12,
					Volumes: []string{"./tests:/app/tests:ro"}},
				// non-agent with test dir: NOT flagged
				{Name: "app", Image: "myorg/app:1.2", VolumesLine: 16,
					Volumes: []string{"./tests:/app/tests"}},
			},
		}},
	}
	var found []Finding
	for _, f := range Evaluate(c) {
		if f.ID == "agent_test_mount" {
			found = append(found, f)
		}
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 agent_test_mount findings (n8n + flowise), got %d: %+v", len(found), found)
	}
	for _, f := range found {
		if f.Severity != SeverityHigh {
			t.Errorf("agent_test_mount should be HIGH, got %s", f.Severity)
		}
	}
}

func TestAgentTestMountVariants(t *testing.T) {
	mk := func(vol string) *collect.Collected {
		return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "c.yml",
			Services: []compose.Service{{Name: "n8n", Image: "n8nio/n8n:1.60", VolumesLine: 4, Volumes: []string{vol}}}}}}
	}
	flagged := func(vol string) bool {
		for _, f := range Evaluate(mk(vol)) {
			if f.ID == "agent_test_mount" {
				return true
			}
		}
		return false
	}
	for _, vol := range []string{
		"./test:/work", "./tests:/work", "./spec:/work", "./fixtures:/work",
		"./__tests__:/work", "./testdata:/work", "./e2e:/work",
	} {
		if !flagged(vol) {
			t.Errorf("%q should trigger agent_test_mount", vol)
		}
	}
	// read-only should not trigger
	if flagged("./tests:/work:ro") {
		t.Error("read-only test mount should NOT trigger")
	}
	// unrelated path
	if flagged("./src:/work") {
		t.Error("non-test path should NOT trigger")
	}
}

func TestAgentAutoRestartDetected(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "n8n", Image: "n8nio/n8n:1.60", Restart: "always", RestartLine: 5},
				{Name: "flowise", Image: "flowiseai/flowise:2.1", Restart: "unless-stopped", RestartLine: 10},
				// on-failure is safe
				{Name: "langflow", Image: "langflowai/langflow:1.1", Restart: "on-failure", RestartLine: 15},
				// non-agent: should NOT be flagged
				{Name: "redis", Image: "redis:7", Restart: "always", RestartLine: 20},
			},
		}},
	}
	var found []Finding
	for _, f := range Evaluate(c) {
		if f.ID == "agent_auto_restart" {
			found = append(found, f)
		}
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 agent_auto_restart findings (n8n + flowise), got %d: %+v", len(found), found)
	}
	if found[0].Severity != SeverityMedium || found[1].Severity != SeverityMedium {
		t.Errorf("agent_auto_restart should be MEDIUM")
	}
	if found[0].Line != 5 || found[1].Line != 10 {
		t.Errorf("wrong lines: %d, %d", found[0].Line, found[1].Line)
	}
}

func TestDockerfileUserRootDetected(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		Dockerfiles: []collect.Dockerfile{
			collect.ParseDockerfile("Dockerfile", "FROM ubuntu:22.04\nRUN apt-get update\nUSER root\nCMD [\"bash\"]\n"),
		},
	}
	var found []Finding
	for _, f := range Evaluate(c) {
		if f.ID == "dockerfile_user_root" {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 dockerfile_user_root finding, got %d", len(found))
	}
	if found[0].Severity != SeverityHigh {
		t.Errorf("dockerfile_user_root (explicit) should be HIGH, got %s", found[0].Severity)
	}
	if found[0].Line != 3 {
		t.Errorf("wrong line: got %d, want 3", found[0].Line)
	}
}

func TestDockerfileUserZeroDetected(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		Dockerfiles: []collect.Dockerfile{
			collect.ParseDockerfile("Dockerfile", "FROM ubuntu:22.04\nUSER 0\nCMD [\"bash\"]\n"),
		},
	}
	var found []Finding
	for _, f := range Evaluate(c) {
		if f.ID == "dockerfile_user_root" {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 dockerfile_user_root finding for USER 0, got %d", len(found))
	}
	if found[0].Severity != SeverityHigh {
		t.Errorf("USER 0 should be HIGH, got %s", found[0].Severity)
	}
}

func TestDockerfileNonRootUserNotFlagged(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		Dockerfiles: []collect.Dockerfile{
			collect.ParseDockerfile("Dockerfile", "FROM ubuntu:22.04\nUSER root\nRUN apt-get update\nUSER appuser\nCMD [\"bash\"]\n"),
		},
	}
	for _, f := range Evaluate(c) {
		if f.ID == "dockerfile_user_root" {
			t.Errorf("final USER appuser should not be flagged as root: %+v", f)
		}
	}
}

func TestDockerfileExposeSensitivePortDetected(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		Dockerfiles: []collect.Dockerfile{
			collect.ParseDockerfile("Dockerfile", "FROM postgres:16\nEXPOSE 5432\nEXPOSE 3000\nUSER postgres\nCMD [\"postgres\"]\n"),
		},
	}
	var sensitive, nonsensitive []Finding
	for _, f := range Evaluate(c) {
		if f.ID == "dockerfile_expose_sensitive" {
			sensitive = append(sensitive, f)
		}
		if f.ID == "dockerfile_expose" {
			nonsensitive = append(nonsensitive, f)
		}
	}
	if len(sensitive) != 1 {
		t.Fatalf("expected 1 dockerfile_expose_sensitive for 5432, got %d", len(sensitive))
	}
	if sensitive[0].Severity != SeverityMedium {
		t.Errorf("dockerfile_expose_sensitive should be MEDIUM, got %s", sensitive[0].Severity)
	}
	if len(nonsensitive) != 1 {
		t.Fatalf("expected 1 dockerfile_expose for 3000, got %d", len(nonsensitive))
	}
	if nonsensitive[0].Severity != SeverityLow {
		t.Errorf("dockerfile_expose should be LOW, got %s", nonsensitive[0].Severity)
	}
}

func TestDockerfileNoUserFlaggedAsMedium(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		Dockerfiles: []collect.Dockerfile{
			collect.ParseDockerfile("Dockerfile", "FROM node:20\nRUN npm install\nCMD [\"node\", \"app.js\"]\n"),
		},
	}
	var found []Finding
	for _, f := range Evaluate(c) {
		if f.ID == "dockerfile_user_root" {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 dockerfile_user_root for no USER, got %d", len(found))
	}
	if found[0].Severity != SeverityMedium {
		t.Errorf("no-USER default-root should be MEDIUM, got %s", found[0].Severity)
	}
}

func TestDockerfileUserRoot(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		Dockerfiles: []collect.Dockerfile{
			collect.ParseDockerfile("agent/Dockerfile", "FROM python:3.12\nRUN pip install langchain\nUSER root\nCMD [\"python\", \"main.py\"]"),
		},
	}
	fs := Evaluate(c)
	found := false
	for _, f := range fs {
		if f.ID == "dockerfile_user_root" && f.Severity == SeverityHigh && f.Line == 3 {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH dockerfile_user_root finding for USER root at line 3")
	}
}

func TestDockerfileNoUserDirective(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		Dockerfiles: []collect.Dockerfile{
			collect.ParseDockerfile("api/Dockerfile", "FROM node:20\nRUN npm install\nCMD [\"node\", \"server.js\"]"),
		},
	}
	fs := Evaluate(c)
	found := false
	for _, f := range fs {
		if f.ID == "dockerfile_user_root" && f.Severity == SeverityMedium && strings.Contains(f.Evidence, "no USER") {
			found = true
		}
	}
	if !found {
		t.Error("expected MEDIUM dockerfile_user_root for missing USER directive")
	}
}

func TestDockerfileNonRootUser(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		Dockerfiles: []collect.Dockerfile{
			collect.ParseDockerfile("worker/Dockerfile", "FROM python:3.12\nUSER 1000\nCMD [\"python\", \"run.py\"]"),
		},
	}
	fs := Evaluate(c)
	for _, f := range fs {
		if f.ID == "dockerfile_user_root" {
			t.Errorf("non-root USER should not trigger dockerfile_user_root, got %+v", f)
		}
	}
}

func TestDockerfileExpose(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		Dockerfiles: []collect.Dockerfile{
			collect.ParseDockerfile("web/Dockerfile", "FROM nginx:latest\nEXPOSE 8080 443/tcp\nUSER nginx"),
		},
	}
	fs := Evaluate(c)
	exposeCount := 0
	for _, f := range fs {
		if f.ID == "dockerfile_expose" {
			exposeCount++
		}
	}
	if exposeCount != 1 {
		t.Errorf("expected 1 EXPOSE finding (one directive), got %d", exposeCount)
	}
}

func TestDatastoreHostNetworkDetected(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "ollama", Image: "ollama/ollama:0.3", Ports: []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434:11434", Line: 3}}},
				{Name: "redis", Image: "redis:7", NetworkMode: "host", NetworkModeLine: 8},
			},
		}},
	}
	var found *Finding
	for _, f := range Evaluate(c) {
		if f.ID == "exposed_datastore" && strings.Contains(f.Evidence, "network_mode: host") {
			ff := f
			found = &ff
		}
	}
	if found == nil {
		t.Fatal("data store on host network not detected")
	}
	if found.Severity != SeverityHigh {
		t.Errorf("data store beside AI on host network should be HIGH, got %s", found.Severity)
	}
}

func TestDatastoreHostNetworkWithoutAIIsMedium(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "app", Image: "myapp:1.0", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 8080, Raw: "8080:8080", Line: 3}}},
				{Name: "pg", Image: "postgres:16", NetworkMode: "host", NetworkModeLine: 7},
			},
		}},
	}
	var found *Finding
	for _, f := range Evaluate(c) {
		if f.ID == "exposed_datastore" && strings.Contains(f.Evidence, "network_mode: host") {
			ff := f
			found = &ff
		}
	}
	if found == nil {
		t.Fatal("data store on host network not detected when alone")
	}
	if found.Severity != SeverityMedium {
		t.Errorf("data store without AI should be MEDIUM, got %s", found.Severity)
	}
}

func TestDatastoreEscalatesAlongsideAgentRuntime(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "n8n", Image: "n8nio/n8n:1.60", Ports: []compose.PortMapping{{HostPort: 5678, TargetPort: 5678, Raw: "127.0.0.1:5678:5678", Line: 3}}},
				{Name: "db", Image: "postgres:16", Ports: []compose.PortMapping{{HostPort: 5432, TargetPort: 5432, Raw: "5432:5432", Line: 6}}},
			},
		}},
	}
	for _, f := range Evaluate(c) {
		if f.ID == "exposed_datastore" && f.Severity != SeverityHigh {
			t.Errorf("data store beside an agent runtime should be HIGH, got %s", f.Severity)
		}
	}
}
