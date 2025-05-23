#!/usr/bin/env bash
#
# Implements a custom target runner.
# This is used transparently by cargo-nextest:
# https://nexte.st/docs/features/target-runners/
# It is defined as a standard feature in cargo:
# https://doc.rust-lang.org/cargo/reference/config.html#targettriplerunner
set -euo pipefail

readonly test_executable_path="${1:-}"
readonly first_test_argument="${2:-}"

# If the test file name contains "integration" and the invocation is not for listing the test, run the test in a container.
# Otherwise run on the host.
if [[ "$test_executable_path" == *integration* ]] && [[ "$first_test_argument" != "--list" ]]; then
  target_dir="$(just get-cargo-target-dir)"

  # if the target dir does not exist then the test will fail
  mkdir -p "$target_dir/debug"

  readonly podman_run_options=(
    --env RUST_LOG=info
    --env RUST_BACKTRACE=1
    # set cargo-llvm-cov profile file to capture coverage data
    --env LLVM_PROFILE_FILE="${LLVM_PROFILE_FILE:-}"
    --rm
    --volume "$PWD:/test"
    --volume "$target_dir/debug:/usr/local/bin"
    --volume "$target_dir:$target_dir"
    --volume "$1:$1"
    archlinux:latest
  )

  podman run "${podman_run_options[@]}" "$@"
else
  "$@"
fi
