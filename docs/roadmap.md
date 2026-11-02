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

- Kubernetes / Helm basics
- ~~Ignore / policy file (`.tasiaignore`)~~ (done: `internal/ignore` package, supports rule IDs, file paths, globs, inline comments)
- ~~Configurable rule severities~~ (done: `.tasiarc.yaml` with `severities:` map, `internal/config` package)

## v1.0

Stable rule IDs, findings JSON schema, documented public API, versioned rule catalog.
