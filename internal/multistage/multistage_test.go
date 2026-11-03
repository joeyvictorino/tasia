package multistage

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func TestAnalyze_MultiStage(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path: "Dockerfile",
				Content: `FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o app .

FROM ubuntu:22.04
COPY --from=builder /app/app /usr/local/bin/app
CMD ["app"]
`,
			},
		},
	}
	c.Dockerfiles[0] = collect.ParseDockerfile("Dockerfile", c.Dockerfiles[0].Content)

	r := Analyze(c)

	if r.Summary.MultiStageFiles != 1 {
		t.Errorf("expected 1 multi-stage file, got %d", r.Summary.MultiStageFiles)
	}
	if r.Summary.TotalStages != 2 {
		t.Errorf("expected 2 stages, got %d", r.Summary.TotalStages)
	}

	hasFatFinal := false
	hasRootFinal := false
	for _, fr := range r.Files {
		for _, f := range fr.Findings {
			if f.RuleID == "multistage_fat_final" {
				hasFatFinal = true
			}
			if f.RuleID == "multistage_root_final" {
				hasRootFinal = true
			}
		}
	}
	if !hasFatFinal {
		t.Error("expected multistage_fat_final finding for ubuntu final stage")
	}
	if !hasRootFinal {
		t.Error("expected multistage_root_final finding (no USER directive)")
	}
}

func TestAnalyze_SingleStage(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM alpine:3.18\nRUN apk add curl\n",
			},
		},
	}
	c.Dockerfiles[0] = collect.ParseDockerfile("Dockerfile", c.Dockerfiles[0].Content)

	r := Analyze(c)
	if r.Summary.SingleStageFiles != 1 {
		t.Errorf("expected 1 single-stage, got %d", r.Summary.SingleStageFiles)
	}
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for single-stage, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyze_ExternalCopy(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path: "Dockerfile",
				Content: `FROM golang:1.21 AS builder
RUN go build -o app .

FROM alpine:3.18
COPY --from=nginx:latest /etc/nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /app /app
USER nobody
CMD ["/app"]
`,
			},
		},
	}
	c.Dockerfiles[0] = collect.ParseDockerfile("Dockerfile", c.Dockerfiles[0].Content)

	r := Analyze(c)

	hasExternalCopy := false
	for _, fr := range r.Files {
		for _, f := range fr.Findings {
			if f.RuleID == "multistage_external_copy" {
				hasExternalCopy = true
			}
		}
	}
	if !hasExternalCopy {
		t.Error("expected multistage_external_copy finding for COPY --from=nginx:latest")
	}
}

func TestAnalyze_UnpinnedBuilder(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path: "Dockerfile",
				Content: `FROM golang AS builder
RUN go build -o app .

FROM alpine:3.18
COPY --from=builder /app /app
USER nobody
CMD ["/app"]
`,
			},
		},
	}
	c.Dockerfiles[0] = collect.ParseDockerfile("Dockerfile", c.Dockerfiles[0].Content)

	r := Analyze(c)

	hasUnpinned := false
	for _, fr := range r.Files {
		for _, f := range fr.Findings {
			if f.RuleID == "multistage_unpinned_builder" {
				hasUnpinned = true
			}
		}
	}
	if !hasUnpinned {
		t.Error("expected multistage_unpinned_builder finding")
	}
}

func TestAnalyze_SecretInFinal(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path: "Dockerfile",
				Content: `FROM golang:1.21 AS builder
RUN go build -o app .

FROM alpine:3.18
RUN --mount=type=secret,id=api_key cat /run/secrets/api_key > /app/.env
COPY --from=builder /app /app
USER nobody
CMD ["/app"]
`,
			},
		},
	}
	c.Dockerfiles[0] = collect.ParseDockerfile("Dockerfile", c.Dockerfiles[0].Content)

	r := Analyze(c)

	hasSecret := false
	for _, fr := range r.Files {
		for _, f := range fr.Findings {
			if f.RuleID == "multistage_secret_final" {
				hasSecret = true
			}
		}
	}
	if !hasSecret {
		t.Error("expected multistage_secret_final finding")
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Files: []FileResult{
			{
				Path: "Dockerfile",
				Stages: []Stage{
					{Image: "golang:1.21", Alias: "builder", Line: 1},
					{Image: "ubuntu:22.04", Line: 5},
				},
				Findings: []Finding{
					{File: "Dockerfile", RuleID: "multistage_fat_final", Severity: "medium", Detail: "test finding", Line: 5},
				},
			},
		},
		Summary: Summary{TotalFiles: 1, MultiStageFiles: 1, TotalStages: 2, TotalFindings: 1},
	}

	out := FormatText(r)
	if !strings.Contains(out, "Multi-Stage Build Security") {
		t.Error("expected header in text output")
	}
	if !strings.Contains(out, "multistage_fat_final") {
		t.Error("expected finding in text output")
	}
}
