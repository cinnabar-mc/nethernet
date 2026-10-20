# Contributing to nethernet project

Thank you for your interest in contributing to `nethernet`!

## Development Environment

1.  **Rust**: Ensure you have the latest stable Rust toolchain installed via [rustup](https://rustup.rs/).
2.  **Formatting**: We use `rustfmt` to ensure consistent code style.
    ```bash
    cargo fmt
    ```
3.  **Linting**: We use `clippy` to catch common mistakes.
    ```bash
    cargo clippy -- -D warnings
    ```

## Running Tests

Run the full test suite, including unit and integration tests:

```bash
cargo test --workspace
```

### Go parity tests and benchmarks

Golden and interop tests compare against go-nethernet through `tools/go-peer`; they skip unless
`NETHERNET_GO_PEER` names a built helper:

```bash
go build -C tools/go-peer -o /tmp/go-peer . && NETHERNET_GO_PEER=/tmp/go-peer cargo test --workspace
```

The CI `bench` job runs `go test -C tools/go-peer -run '^$' -bench .` and the criterion benches on one runner,
then compares them with `go tool bench-compare --go-procs N` from `tools/go-peer`, where N is the `-cpu` value.

## Pull Requests

1.  Fork the repository.
2.  Create a new feature branch (`git checkout -b my-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-feature`).
5.  Open a Pull Request.

Please ensure all tests pass and that you've added new tests for any new functionality.
