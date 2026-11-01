# Threat Model

Tasia is a local static analyzer for deployment artifacts.

## In scope

- Misconfigurations in compose files and `.env*` files that cause private AI services to be reachable beyond localhost or the intended container network.
- Agent runtimes and workflow engines (n8n, Flowise, Langflow, Dify, OpenHands and similar) that execute tools or model-written code: their exposure is a remote code-execution surface, and a writable mount of the project lets the agent alter the tests or check scripts that are supposed to judge its own work. Tasia flags both from the compose file alone.
- Dockerfiles are collected, but no rule analyzes them yet (planned, see the roadmap).
- Accidental secret key name leakage (names only).
- Mutable image tags.

## Out of scope

- Runtime exploitation or active scanning of running services.
- Analysis of application source or model weights.
- Network ACLs on the actual host or cloud provider.
- Proving compliance.

## Assumptions

- The user runs Tasia on their own machine / CI against their own files.
- No secrets are committed (Tasia helps spot the risk).
- Findings are reviewed by humans before action.
- Where an agent runtime is present, its approval mode (auto-approve versus per-step confirmation) is a runtime setting Tasia cannot see; the rules cover what the compose file does show, which is reachability and what the agent can write to.
