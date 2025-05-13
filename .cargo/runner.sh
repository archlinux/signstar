#!/usr/bin/env bash
#
# Implements a custom target runner.
# This is used transparently by cargo-nextest:
# https://nexte.st/docs/features/target-runners/
# It is defined as a standard feature in cargo:
# https://doc.rust-lang.org/cargo/reference/config.html#targettriplerunner
set -euo pipefail

# If the test file name contains "integration" and the invocation is not for listing the test, run the test in a container.
# Otherwise run on the host.
if [[ "$1" == *integration* ]] && [[ "$2" != "--list" ]]; then
  target_dir="$(just get-cargo-target-dir)"
  readonly podman_run_options=(
    --env RUST_LOG=info
    --env RUST_BACKTRACE=1
    --rm
    --volume "$PWD:/test"
    --volume "$target_dir/debug:/usr/local/bin"
    --volume "$1:$1"
    archlinux:latest
  )

  podman run "${podman_run_options[@]}" "$@"
else
  "$@"
fi
