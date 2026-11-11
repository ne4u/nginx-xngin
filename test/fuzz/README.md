Fuzz targets live with their SDKs so `go test -fuzz` / `cargo fuzz` work
in place:

- Go: `cd agents/go && go test -fuzz=FuzzFrames -fuzztime=30s ./xngin`
- Rust: copy `fuzz_codec.rs` as a cargo-fuzz target (see header comment).
- Module side: run `test/harness/stub_agent.py` with garbage/malformed
  responses (the integration suite already covers conn reset + garbage).
