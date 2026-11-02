# Roadmap

## v0.1 — Compose hardening (current)

- `review`, `ci`, `install`/`uninstall --pre-push`, `explain`, `version`
- 12 deterministic rules with real line numbers via yaml.v3 nodes (including `network_mode: host`)
- Detection: Ollama, vLLM, llama.cpp, LM Studio, Open WebUI, Gradio,
  Qdrant, Chroma, Weaviate, Milvus, Redis, Postgres
- Agent runtimes as a category (n8n, Flowise, Langflow, Dify, OpenHands,
  Open Interpreter, Memdoor, CrewAI, AutoGen): `exposed_agent_runtime`,
  `broad_bind_mount` raised to HIGH on a runtime that can rewrite the
  project that checks its own work, listed as `agent_runtimes` in the
  stack manifest (13 rules)
- Full `.tasia/` hardening pack (never edits your files)
- Optional local `explain` via Ollama (redacted findings only)
- Prebuilt binaries (darwin/linux, arm64/amd64) with checksums

## v0.2

- ~~GitHub Action + SARIF output~~ (done: `--format sarif`, `.github/workflows/sarif.yml`)
- ~~Agent-runtime follow-ups: flag auto-approve settings where a product
  exposes them in compose `environment:` (key names only), and warn when
  test or fixture directories are mounted writable into an agent service~~
  (done: `agent_auto_approve`, `agent_test_mount`, `agent_auto_restart`)
- ~~Caddyfile / nginx auth checks~~ (done: `reverse_proxy_no_auth`)
- ~~Chroma / Weaviate auth hints~~ (done: `vector_db_no_auth`)
- ~~Dockerfile `USER root` / `EXPOSE` analysis~~ (done: `dockerfile_user_root`, `dockerfile_expose`, `dockerfile_expose_sensitive`)

## v0.3

- ~~Kubernetes / Helm basics~~ (done: `kube_exposed_service`, `kube_privileged`, `kube_run_as_root`, `kube_host_network`, `kube_host_path`)
- ~~Ignore / policy file (`.tasiaignore`)~~ (done: `internal/ignore` package, supports rule IDs, file paths, globs, inline comments)
- ~~Configurable rule severities~~ (done: `.tasiarc.yaml` with `severities:` map, `internal/config` package)

## v1.0

- ~~Stable rule IDs~~ (done: `RuleInfo.ID` in `internal/rules/catalog.go`, same IDs across `.tasiaignore`, `.tasiarc.yaml`, `--format json`)
- ~~Findings JSON schema~~ (done: `tasia schema` command, `docs/findings-schema.json`, `schema_version` field in `--format json` output)
- ~~Versioned rule catalog~~ (done: `tasia rules --format json` prints every rule with stable fields)
- ~~Documented public Go API~~ (done: godoc package comments on all 8 packages: rules, report, collect, collect/compose, ignore, config, cli, llm)
