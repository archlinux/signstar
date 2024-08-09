#!/usr/bin/env -S just --working-directory . --justfile
# Load project-specific properties from the `.env` file

set dotenv-load := true

# Whether to run ignored tests (set to "true" to run ignored tests)

ignored := "false"

# Runs all checks and tests. Since this is the first recipe it is run by default.
run-pre-commit-hook: check test

# Runs all check targets
check: check-spelling check-formatting lint check-dependencies check-licenses

# Faster checks need to be executed first for better UX.  For example
# codespell is very fast. cargo fmt does not need to download crates etc.

# Installs all tools required for development
dev-install: install-pacman-dev-packages install-rust-dev-tools

# Installs development packages using pacman
install-pacman-dev-packages:
    # All packages are set in the `.env` file
    pacman -Syu --needed --noconfirm $PACMAN_DEV_PACKAGES

# Installs all Rust tools required for development
install-rust-dev-tools:
    rustup default stable
    rustup component add clippy
    rustup toolchain install nightly
    rustup component add --toolchain nightly rustfmt

# Checks commit messages for correctness
check-commits:
    #!/usr/bin/env bash
    set -euo pipefail

    readonly default_branch="${CI_DEFAULT_BRANCH:-main}"

    if ! git rev-parse --verify "origin/$default_branch" > /dev/null 2>&1; then
        printf "The default branch '%s' does not exist!\n" "$default_branch" >&2
        exit 1
    fi

    tmpdir="$(mktemp --dry-run --directory)"
    readonly check_tmpdir="$tmpdir"
    mkdir -p "$check_tmpdir"

    # remove temporary dir on exit
    cleanup() (
      if [[ -n "${check_tmpdir:-}" ]]; then
        rm -rf "${check_tmpdir}"
      fi
    )

    trap cleanup EXIT

    for commit in $(git rev-list "origin/${default_branch}.."); do
        printf "Checking commit %s\n" "$commit"

        commit_message="$(git show -s --format=%B "$commit")"
        codespell_config="$(mktemp --tmpdir="$check_tmpdir")"

        # either use the commit's .codespellrc or create one
        if git show "$commit:.codespellrc" > /dev/null 2>&1; then
            git show "$commit:.codespellrc" > "$codespell_config"
        else
            printf "[codespell]\nskip = .cargo,.git,target,.env,Cargo.lock\nignore-words-list = crate,passt\n" > "$codespell_config"
        fi

        if ! rg -q "Signed-off-by: " <<< "$commit_message"; then
            printf "Commit %s ❌️\n" "$commit" >&2
            printf "The commit message lacks a \"Signed-off-by\" line.\n" >&2
            printf "%s\n" \
                "  Please use:" \
                "    git rebase --signoff main && git push --force-with-lease" \
                "  See https://developercertificate.org/ for more details." >&2
            exit 1
        elif ! codespell --config "$codespell_config" - <<< "$commit_message"; then
            printf "Commit %s ❌️\n" "$commit" >&2
            printf "The spelling of the commit message needs improvement.\n" >&2
            exit 1
        elif ! cog verify "$commit_message"; then
            printf "Commit %s ❌️\n" "$commit" >&2
            printf "%s\n" \
                "The commit message is not a conventional commit message:" \
                "$commit_message" \
                "See https://www.conventionalcommits.org/en/v1.0.0/ for more details." >&2
            exit 1
        else
            printf "Commit %s ✅️\n\n" "$commit"
        fi
    done

# Runs checks before pushing commits to remote repository.
run-pre-push-hook: check-commits

# Checks common spelling mistakes
check-spelling:
    codespell

# Checks source code formatting
check-formatting:
    just --unstable --fmt --check
    # We're using nightly to properly group imports, see rustfmt.toml
    cargo +nightly fmt -- --check

# Updates the local cargo index and displays which crates would be updated
dry-update:
    cargo update --dry-run --verbose

# Lints the source code
lint:
    tangler bash < nethsm-cli/README.md | shellcheck --shell bash -
    cargo clippy --all -- -D warnings

# Checks for issues with dependencies
check-dependencies: dry-update
    cargo deny --all-features check

# Checks licensing status
check-licenses:
    reuse lint

# Runs all unit tests. By default ignored tests are not run. Run with `ignored=true` to run only ignored tests
test:
    {{ if ignored == "true" { "cargo test --all -- --ignored" } else { "cargo test --all && RUSTFLAGS='-D warnings' cargo doc --no-deps" } }}

# Runs per project end-to-end tests found in a project README.md
test-readme project:
    #!/usr/bin/env bash
    set -euxo pipefail

    CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"

    container_id=""

    install_executables() {
        printf "Installing executables of %s...\n" "{{ project }}"
        cargo install --locked --path {{ project }}
    }

    create_container() {
        container_id="$(podman container create --rm --network=pasta:-t,auto,-u,auto,-T,auto,-U,auto docker.io/nitrokey/nethsm:testing)"
    }

    start_container() {
        podman container start "$container_id" > /dev/null
    }

    stop_container() {
        podman container stop "$container_id" > /dev/null
    }

    trap stop_container EXIT

    install_executables
    create_container
    start_container

    PATH="$CARGO_HOME/bin:$PATH"
    printf "PATH=%s\n" "$PATH"

    cd {{ project }} && PATH="$PATH" tangler bash < README.md | bash -euxo pipefail -

# Adds pre-commit and pre-push git hooks
add-hooks:
    #!/usr/bin/env bash
    set -euo pipefail

    echo just run-pre-commit-hook > .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit

    echo just run-pre-push-hook > .git/hooks/pre-push
    chmod +x .git/hooks/pre-push

# Fixes common issues. Files need to be git add'ed
fix:
    #!/usr/bin/env bash
    set -euo pipefail

    if ! git diff-files --quiet ; then
        echo "Working tree has changes. Please stage them: git add ."
        exit 1
    fi

    codespell --write-changes
    just --unstable --fmt
    cargo clippy --fix --allow-staged

    # fmt must be last as clippy's changes may break formatting
    cargo +nightly fmt
