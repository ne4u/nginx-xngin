# Contributing

## Setup

You need: an nginx source tarball, clang/gcc, Go 1.22+, the Rust
toolchain, and Python 3 + pytest. `AGENTS.md` has the authoritative
build/test commands — read it first.

```sh
# build the module against nginx source
cd nginx-<ver>
./configure --add-dynamic-module=/path/to/repo/module \
            --with-http_ssl_module
make modules

# test everything
python3 -m pytest test/harness -q
(cd agents/go && go test ./... && go vet ./...)
(cd agents/rust && cargo test)
export XNGIN_NGINX_BIN=/path/to/nginx
export XNGIN_MODULE_SO=/path/to/objs/ngx_http_xngin_module.so
python3 -m pytest test/cases -q
```

## Rules

- **`SPEC.md` is normative.** Any wire-format change updates the spec,
  all three codecs, and `test/conformance/vectors.json` — regenerate
  with `python3 test/conformance/gen_vectors.py`.
- C module: nginx-style C, no external dependencies, no locks on the
  hot path.
- All tests must pass; add coverage for new verdict fields,
  capabilities, or directives.
- Never commit secrets, `.env` files, certs/keys, or `history_*.md`.
  `.gitignore` covers the usual cases — double-check `git status`
  before pushing.

## PRs

Keep changes small and focused. Describe *why*, and paste test
evidence in the PR. See `.github/PULL_REQUEST_TEMPLATE.md`.
