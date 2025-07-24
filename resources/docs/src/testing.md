# Testing

Signstar contains several forms of tests, which behave differently depending on the scope of the test.

## Test types

### Unit tests

They are regular Rust tests, either marked with the standard `#[test]` attribute or with a parametrization-capable `#[rstest]` using the [`rstest` crate].

For convenience `just test` runs them all using `cargo nextest` for maximum parallelism.

### Doc tests

Our documentation is tested to validate if the examples are using latest API.

Due to a [`nextest` limitation] these need to be run using the standard `cargo` tooling.

For convenience `just test-docs` runs them all.

### README tests

These tests extract shell fragments from `README.md` documents in our projects and run them.
This makes sure that the examples using Signstar binaries are also up to date.
Some of these tests use a virtual NetHSM in a container or run in a dedicated Arch Linux container.

For convenience `just test-readmes` runs them all.

### NetHSM integration tests

Several Rust tests require a running NetHSM container.
NetHSM tests, marked with a `_nethsm-integration-test` feature fall into this category.

For convenience `just nethsm-integration-tests` runs all NetHSM tests.

### Containerized integration tests

Some tests need to be run in a container, as they depend on global system state.
These are marked with a `_containerized-integration-test` feature.
A custom runner script (`.cargo/runner.sh`) ensures that matching tests are run in a dedicated Arch Linux container each.

For convenience `just containerized-integration-tests` runs all containerized tests.

## Code coverage

All tests (with the exception of doc tests due to a [`llvm-cov` limitation]) gather code coverage data if the `SIGNSTAR_COVERAGE` environment variable is set to `true`.
This is done automatically in CI and the coverage results are displayed inline in merge request diffs.
The numeric values and changes with regards to the `main` branch are additionally displayed in the MR view.

[`llvm-cov` limitation]: https://github.com/taiki-e/cargo-llvm-cov/issues/440
[`nextest` limitation]: https://github.com/nextest-rs/nextest/issues/16
[`rstest` crate]: https://docs.rs/rstest/latest/rstest/attr.rstest.html
