# Contributing to Tasia

Issues and pull requests are welcome.

## Development

- Go 1.26+ (see `go.mod`)
- Build: `go build -o tasia ./cmd/tasia`
- Test: `go test ./... -race -count=1`
- Lint (what CI runs): `gofmt -l .` must print nothing, `go vet ./...`, and `go mod tidy` must leave `go.mod` and `go.sum` unchanged
- Try it: `go run ./cmd/tasia review --path examples/messy-ollama-stack --no-write`

CI also checks the documented exit codes against `examples/`, so a change to gate behaviour needs the README and the workflow updated together.

## Adding a rule

1. If the rule needs new config data, extract it in `internal/collect` (compose parsing is in `internal/collect/compose`).
2. Add the rule in `internal/rules/rules.go`, returning a `rules.Finding` with id, severity, title, file, line, evidence, why and fix.
3. Never emit secret values. Evidence is a key name, port, image or the flagged config token.
4. Add a table-driven test in `internal/rules/rules_test.go` (or a fixture under `testdata/`).
5. Update `docs/rules.md` and the table in `README.md`.

## Reporting issues

Please include:
- the output of `tasia version`
- the compose or config snippet, with secrets removed
- the output of `tasia review --format json --no-write`

Security problems in Tasia itself go through the private route in [`SECURITY.md`](SECURITY.md), not a public issue.

## Conduct

Be respectful and keep the discussion on the problem: private AI deployments shipping with overly permissive exposure.
