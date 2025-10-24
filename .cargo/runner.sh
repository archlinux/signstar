#!/usr/bin/env bash
#
# Implements a custom target runner.
# This is used transparently by cargo-nextest:
# https://nexte.st/docs/features/target-runners/
# It is defined as a standard feature in cargo:
# https://doc.rust-lang.org/cargo/reference/config.html#targettriplerunner
#
# When this is used via cargo-nextest, this runner script is called in two different scenarios (with differing arguments):
#
# - Once to list all tests provided by a test executable (`<file> --list --format terse`),
# - another time to run each individual test that the executable provides (`<file> <test-name> --nocapture --exact`).
#
# For details see: https://nexte.st/docs/design/custom-test-harnesses/#manually-implementing-a-test-harness
set -euo pipefail

readonly test_executable_path="${1:-}"
readonly first_test_argument="${2:-}"
# Use Arch Linux's container registry when running in CI (indicated by the presence of the `CI` environment variable).
if [[ -z "${CI+x}" ]]; then
  arch_container="archlinux:latest"
else
  arch_container="registry.archlinux.org/archlinux/archlinux-docker:base-master"
fi

# If the test file name contains "integration" and the invocation is not for listing the test, run the test in a container.
# Otherwise run on the host.
if [[ "$test_executable_path" == *integration* ]] && [[ "$first_test_argument" != "--list" ]]; then
  target_dir="$(just get-cargo-target-dir)"

  readonly podman_run_options=(
    # set cargo-llvm-cov profile file to capture coverage data
    --env LLVM_PROFILE_FILE="${LLVM_PROFILE_FILE:-}"
    --env CARGO_LLVM_COV="${CARGO_LLVM_COV:-}"
    --env CARGO_LLVM_COV_SHOW_ENV="${CARGO_LLVM_COV_SHOW_ENV:-}"
    --env CARGO_LLVM_COV_TARGET_DIR="${CARGO_LLVM_COV_TARGET_DIR:-}"
    --env RUSTFLAGS="${RUSTFLAGS:-}"
    --env RUSTDOCFLAGS="${RUSTDOCFLAGS:-}"
    --env RUST_LOG=info
    --env RUST_BACKTRACE=1
    # Create network namespace, but no network setup for the container.
    --network=none
    --rm
    # Mounts the current working directory into the container.
    --volume "$PWD:/test"
    # Mounts the user's cargo target directory into the container.
    --volume "$target_dir/debug:/usr/local/bin"
    # Mount the test executable into the container at the same location as on the host
    --volume "$test_executable_path:$test_executable_path"
    # Mount the target dir so that coverage data is written to correct location
    --volume "$target_dir:$target_dir"
    "$arch_container"
  )

  podman run "${podman_run_options[@]}" "$@"
else
  "$@"
fi
