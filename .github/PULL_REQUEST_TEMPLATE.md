## What & why

## Test evidence
- [ ] `python3 -m pytest test/harness -q`
- [ ] `go test ./... && go vet ./...` (agents/go)
- [ ] `cargo test` (agents/rust)
- [ ] `python3 -m pytest test/cases -q` (integration)

## Spec
- [ ] SPEC.md updated (if wire format changed)
- [ ] conformance vectors regenerated (if wire format changed)
