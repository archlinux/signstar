#!/usr/bin/env -S just --working-directory . --justfile
# Load project-specific properties from the `.env` file

set dotenv-load := true

# Whether coverage reports should be generated when running tests.

coverage := env("SIGNSTAR_COVERAGE", "false")

# The output directory for documentation artifacts

output_dir := "output"

# Lists all available recipes.
[private]
@default:
    just --list

# Runs all check recipes (except those for commit messages).
[group('check')]
check: check-spelling check-formatting check-shell-code check-rust-code check-rust-derives check-unused-deps check-dependencies check-licenses check-links

# Faster checks need to be executed first for better UX.  For example
# codespell is very fast. cargo fmt does not need to download crates etc.

# Installs all tools required for development
[group('dev')]
dev-install: install-pacman-dev-packages install-rust-dev-tools

# Installs development packages using pacman
[group('dev')]
install-pacman-dev-packages:
    # All packages are set in the `.env` file
    run0 pacman -S --needed --noconfirm $PACMAN_PACKAGES

# Installs all Rust tools required for development
[group('dev')]
install-rust-dev-tools:
    rustup default stable
    rustup component add clippy
    rustup toolchain install nightly
    rustup component add --toolchain nightly rustfmt llvm-tools-preview

# Ensures that one or more required commands are installed
[private]
ensure-command +command:
    #!/usr/bin/env bash
    set -euo pipefail

    read -r -a commands <<< "{{ command }}"

    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" > /dev/null 2>&1 ; then
            printf "Couldn't find required executable '%s'\n" "$cmd" >&2
            exit 1
        fi
    done

# Checks commit messages for correctness
[group('check')]
check-commits:
    #!/usr/bin/env bash
    set -euo pipefail

    readonly default_branch="${CI_DEFAULT_BRANCH:-main}"

    just ensure-command codespell cog git rg

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

# Checks common spelling mistakes
[group('check')]
check-spelling:
    just ensure-command codespell
    codespell

# Gets names of all workspace members
[private]
get-workspace-members:
    just ensure-command cargo jq
    cargo metadata --format-version=1 |jq -r '.workspace_members[] | capture("/(?<name>[a-z-]+)#.*").name'

# Checks if a string matches a workspace member exactly
[private]
is-workspace-member package:
    #!/usr/bin/env bash
    set -euo pipefail

    mapfile -t workspace_members < <(just get-workspace-members 2>/dev/null)

    for name in "${workspace_members[@]}"; do
        if [[ "$name" == {{ package }} ]]; then
            exit 0
        fi
    done
    exit 1

# Gets metadata version of a workspace member
[private]
get-workspace-member-version package:
    #!/usr/bin/env bash
    set -euo pipefail

    just ensure-command cargo jq

    readonly version="$(cargo metadata --format-version=1 |jq -r --arg pkg {{ package }} '.workspace_members[] | capture("/(?<name>[a-z-]+)#(?<version>[0-9.]+)") | select(.name == $pkg).version')"

    if [[ -z "$version" ]]; then
        printf "No version found for package %s\n" {{ package }} >&2
        exit 1
    fi

    printf "$version\n"

# Checks for unused dependencies
[group('check')]
check-unused-deps:
    #!/usr/bin/env bash
    set -euxo pipefail

    just ensure-command cargo-machete

    for name in $(just get-workspace-members); do
        cargo machete "$name"
    done

# Checks for consistent sorting of rust derives
[group('check')]
check-rust-derives:
    cargo sort-derives --check

# Checks source code formatting
[group('check')]
check-formatting:
    just ensure-command mado rustup taplo
    just --unstable --fmt --check
    # We're using nightly to properly group imports, see rustfmt.toml
    cargo +nightly fmt -- --check

    taplo format --check

    mado check

# Updates the local cargo index and displays which crates would be updated
[private]
dry-update:
    just ensure-command cargo
    cargo update --dry-run --verbose

# Checks shell code using shellcheck.
[group('check')]
check-shell-code:
    just check-shell-readme nethsm-cli
    just check-shell-readme signstar-configure-build
    just check-shell-readme signstar-request-signature

    just check-shell-recipe 'test-readme nethsm-cli'
    just check-shell-recipe check-commits
    just check-shell-recipe check-unused-deps
    just check-shell-recipe ci-publish
    just check-shell-recipe 'generate shell_completions nethsm-cli'
    just check-shell-recipe 'is-workspace-member nethsm'
    just check-shell-recipe 'release nethsm'
    just check-shell-recipe docs
    just check-shell-recipe flaky
    just check-shell-recipe test
    just check-shell-recipe 'ensure-command test'
    just check-shell-recipe 'get-latest-nethsm-release-short-commit'

    just check-shell-script .cargo/runner.sh

# Checks the Rust source code using cargo-clippy.
[group('check')]
check-rust-code:
    just ensure-command cargo cargo-clippy mold
    cargo clippy --all-features --all-targets --workspace -- -D warnings

# Checks a shell script using shellcheck.
[group('check')]
check-shell-script file:
    just ensure-command shellcheck
    shellcheck --shell bash {{ file }}

# Checks the script examples of a project's README using shellcheck.
[group('check')]
check-shell-readme project:
    just ensure-command shellcheck tangler
    tangler bash < {{ project }}/README.md | shellcheck --shell bash -

# Checks justfile recipe relying on shell semantics using shellcheck.
[group('check')]
check-shell-recipe recipe:
    just ensure-command rg shellcheck
    just -vv -n {{ recipe }} 2>&1 | rg -v '===> Running recipe' | shellcheck -

# Checks for issues with dependencies
[group('check')]
check-dependencies: dry-update
    just ensure-command cargo-deny
    cargo deny --all-features check

# Checks licensing status
[group('check')]
check-licenses:
    just ensure-command reuse
    reuse lint

# Build project and optionally provide further `cargo-build` options
[group('build')]
build project *cargo_build_options:
    just ensure-command cargo
    cargo build -p {{ project }} {{ cargo_build_options }}

# Build local documentation
[group('build')]
docs:
    #!/usr/bin/env bash
    set -euo pipefail

    just ensure-command cargo mold

    readonly target_dir="${CARGO_TARGET_DIR:-$PWD/target}"
    mapfile -t workspace_members < <(just get-workspace-members 2>/dev/null)

    # NOTE: nethsm-cli's executable documentation shadows the nethsm documentation (because of cargo bug: https://github.com/rust-lang/cargo/issues/6313)
    for name in "${workspace_members[@]}"; do
        RUSTDOCFLAGS='-D warnings' cargo doc --document-private-items --no-deps --package "$name"
        case "$name" in
            nethsm)
                mv "$target_dir/doc/nethsm" "$target_dir/doc/nethsm.tmp"
            ;;
            nethsm-cli)
                rm -rf "$target_dir/doc/nethsm"
            ;;
            *)
            ;;
        esac
    done
    mv "$target_dir/doc/nethsm.tmp" "$target_dir/doc/nethsm"

# Runs all unit tests
[group('test')]
test:
    #!/usr/bin/env bash
    set -euxo pipefail

    readonly coverage="{{ coverage }}"

    if [[ "$coverage" == "true" ]]; then
        just ensure-command cargo cargo-llvm-cov cargo-nextest mold
        cargo llvm-cov --no-report nextest --locked --all
    else
        just ensure-command cargo cargo-nextest mold
        cargo nextest run --locked --all
    fi
    just test-docs
    just docs

# Runs all doc tests
[group('test')]
test-docs:
    #!/usr/bin/env bash
    set -euo pipefail

    readonly coverage="{{ coverage }}"

    if [[ "$coverage" == "true" ]]; then
        just ensure-command cargo cargo-llvm-cov
        cargo +nightly llvm-cov --no-report --doc --locked
    else
        just ensure-command cargo
        cargo test --locked --doc
    fi

# Runs per project end-to-end tests found in a project README.md
[group('test')]
test-readme project:
    #!/usr/bin/env bash
    set -euxo pipefail

    readonly project="{{ project }}"
    readonly cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    container_id=""
    # Use Arch Linux's container registry when running in CI (indicated by the presence of the `CI` environment variable).
    if [[ -z "${CI+x}" ]]; then
      arch_container="archlinux:latest"
    else
      arch_container="registry.archlinux.org/archlinux/archlinux-docker:base-master"
    fi
    podman_create_options=(
        --rm
        '--network=pasta:-t,auto,-u,auto,-T,auto,-U,auto'
    )
    podman_start_options=()

    case "$project" in
        signstar-configure-build)
            podman_create_options+=(
                --interactive
                --tty
                "--mount=type=bind,source=$cargo_home/bin,destination=/usr/local/bin,ro=true"
                "--mount=type=bind,source=$project,destination=/mnt,ro=true"
                --workdir=/mnt
                "$arch_container"
                sh -c 'pacman-key --init && pacman -Sy --needed --noconfirm archlinux-keyring && pacman -Syu --needed --noconfirm tangler && tangler bash < /mnt/README.md | bash -euxo pipefail -'
            )
            podman_start_options+=(
                --attach
            )
        ;;
        signstar-request-signature)
            podman_create_options+=(
                --init
                "--mount=type=bind,source=$project/tests/sshd/10-signstar-sign.conf,destination=/etc/ssh/sshd_config.d/10-signstar-sign.conf,ro=true"
                "--mount=type=bind,source=$project/tests/sshd,destination=/home/signstar-sign/.ssh,ro=true"
                "--mount=type=bind,source=$project/tests/sshd/signstar-sign,destination=/usr/local/bin/signstar-sign,ro=true"
                "$arch_container"
                sh -c "pacman-key --init && pacman -Sy --needed --noconfirm archlinux-keyring && pacman -Syu --needed --noconfirm openssh && useradd signstar-sign && ssh-keygen -A && /usr/bin/sshd -p 2222 -e -D"
                )
        ;;
        *)
            podman_create_options+=(
                docker.io/nitrokey/nethsm:c16fe4ed
            )
        ;;
    esac

    just ensure-command cargo mold podman tangler

    install_executables() {
        printf "Installing executables of %s...\n" "{{ project }}"
        case "$project" in
            nethsm-cli)
                cargo install --locked --path signstar-request-signature
            ;;
        esac
        cargo install --locked --path {{ project }}
    }

    create_container() {
        container_id="$(podman container create "${podman_create_options[@]}")"
    }

    start_container() {
        podman container start "${podman_start_options[@]}" "$container_id"
    }

    stop_container() {
        if podman container exists "$container_id" > /dev/null; then
            # NOTE: Due to podman's state handling the container may just not be entirely gone when checking for its existence.
            #       Relying on the status code of `podman container stop` would lead to flaky behavior, as sometimes the container is already gone when trying to stop it.
            set +e
            podman container stop "$container_id" >/dev/null 2>&1
            set -e
        fi
    }

    run_test() {
        start_container
        case "$project" in
            signstar-configure-build)
                # NOTE: the test is run by starting the container
                exit 0
            ;;
            *)
                # NOTE: the test is run on the calling host against a nethsm container
                cd "$project" && tangler bash < README.md | PATH="$cargo_home/bin:$PATH" bash -euxo pipefail -
            ;;
        esac
    }

    trap stop_container EXIT

    install_executables
    create_container
    run_test

# Runs end-to-end tests found in project README.md files for all projects supporting it
[group('test')]
test-readmes:
    just test-readme nethsm-cli
    just test-readme signstar-configure-build
    just test-readme signstar-request-signature

# Runs checks and tests before a commit.
[private]
run-pre-commit-hook: check test

# Runs checks before pushing commits to remote repository.
[private]
run-pre-push-hook: check-commits

# Adds pre-commit and pre-push git hooks
[group('git')]
add-hooks:
    #!/usr/bin/env bash
    set -euo pipefail

    echo just run-pre-commit-hook > .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit

    echo just run-pre-push-hook > .git/hooks/pre-push
    chmod +x .git/hooks/pre-push

    cat > .git/hooks/prepare-commit-msg <<'EOL'
    #!/bin/sh

    COMMIT_MSG_FILE=$1
    COMMIT_SOURCE=$2

    SOB=$(git var GIT_COMMITTER_IDENT | sed -n 's/^\(.*>\).*$/Signed-off-by: \1/p')
    git interpret-trailers --in-place --trailer "$SOB" "$COMMIT_MSG_FILE"
    if test -z "$COMMIT_SOURCE"; then
        /usr/bin/perl -i.bak -pe 'print "\n" if !$first_line++' "$COMMIT_MSG_FILE"
    fi
    EOL
    chmod +x .git/hooks/prepare-commit-msg

# Check for stale links in documentation
[group('check')]
check-links:
    just ensure-command lychee
    lychee .

# Fixes common issues. Files need to be git add'ed
[group('dev')]
fix:
    #!/usr/bin/env bash
    set -euo pipefail

    just ensure-command cargo-clippy codespell git mold rustup

    if ! git diff-files --quiet ; then
        echo "Working tree has changes. Please stage them: git add ."
        exit 1
    fi

    codespell --write-changes
    just --unstable --fmt
    cargo clippy --fix --allow-staged
    taplo format

    cargo sort-derives

    # fmt must be last as clippy's changes may break formatting
    cargo +nightly fmt

render-script := '''
    //! ```cargo
    //! [dependencies]
    //! pkg = { path = "PATH", package = "PKG" }
    //! clap_allgen = "0.2.1"
    //! ```

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        clap_allgen::render_KIND::<pkg::cli::Cli>(
            &std::env::args().collect::<Vec<_>>()[1],
        )?;
        Ok(())
    }
'''

# Render `manpages` or `shell_completions` (`kind`) of a given package (`pkg`).
[group('build')]
generate kind pkg:
    #!/usr/bin/bash

    set -Eeuo pipefail

    readonly output_dir="${CARGO_TARGET_DIR:-$PWD/output}"
    mkdir --parents "$output_dir"

    readonly kind="{{ kind }}"

    just ensure-command rust-script sed

    case "$kind" in
      manpages|shell_completions)
          ;;
      *)
          printf 'Only "manpages" and "shell_completions" are supported.\n'
          exit 1
    esac

    script="$(mktemp --suffix=.rs)"
    sed "s/PKG/{{ pkg }}/;s#PATH#$PWD/{{ pkg }}#g;s/KIND/{{ kind }}/g" > "$script" <<< '{{ render-script }}'
    rust-script "$script" "$output_dir/{{ kind }}"
    rm --force "$script"

# Continuously run integration tests for a given number of rounds
[group('test')]
flaky test='just test-readme nethsm-cli' rounds='999999999999':
    #!/usr/bin/bash
    set -euo pipefail

    seq 1 {{ rounds }} | while read -r counter; do
      printf "Running flaky tests (%d/{{ rounds }})...\n" "$counter"
      sleep 1
      {{ test }}
      echo
    done

# Prepares the release of a crate by updating dependencies, incrementing the crate version and creating a changelog entry (optionally, the version can be set explicitly)
[group('release')]
prepare-release package version="":
    #!/usr/bin/env bash
    set -euo pipefail

    readonly package_name="{{ package }}"
    if [[ -z "$package_name" ]]; then
        printf "No package name provided!\n"
        exit 1
    fi
    readonly package_version="{{ version }}"
    branch_name=""

    just ensure-command git release-plz

    release-plz update -u -p "$package_name"

    # NOTE: When setting the version specifically, we are likely in a situation where `release-plz` did not detect a version change (e.g. when only changes to top-level files took place since last release).
    # In this case we are fine to potentially have no changes in the CHANGELOG.md or having to adjust it manually afterwards.
    if [[ -n "$package_version" ]]; then
        release-plz set-version "${package_name}@${package_version}"
    fi

    # make sure that the current version would be publishable, but ignore files not added to git
    cargo publish -p "$package_name" --dry-run --allow-dirty

    readonly updated_package_version="$(just get-workspace-member-version "$package_name")"

    if [[ -n "$package_version" ]]; then
        branch_name="release/$package_name/$package_version"
    else
        branch_name="release/$package_name/$updated_package_version"
    fi
    git checkout -b "$branch_name"

    git add Cargo.* "$package_name"/{Cargo.toml,CHANGELOG.md}
    git commit --gpg-sign --signoff --message "chore: Upgrade $package_name crate to $updated_package_version"
    git push --set-upstream origin "$branch_name"

# Creates a release of a crate in the workspace by creating a tag and pushing it
[group('release')]
release package:
    #!/usr/bin/env bash
    set -euo pipefail

    readonly package_version="$(just get-workspace-member-version {{ package }})"
    if [[ -z "$package_version" ]]; then
        exit 1
    fi
    readonly current_version="{{ package }}/$package_version"

    just ensure-command git

    if [[ -n "$(git tag -l "$current_version")" ]]; then
        printf "The tag %s exists already!\n" "$current_version" >&2
        exit 1
    fi

    printf "Creating tag %s...\n" "$current_version"
    git tag -s "$current_version" -m "$current_version"
    printf "Pushing tag %s...\n" "$current_version"
    git push origin refs/tags/"$current_version"

# Publishes a crate in the workspace from GitLab CI in a pipeline for tags
[group('release')]
ci-publish:
    #!/usr/bin/env bash
    set -euo pipefail

    # an auth token with publishing capabilities is expected to be set in GitLab project settings
    readonly token="${CARGO_REGISTRY_TOKEN:-}"
    # rely on predefined variable to retrieve git tag: https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
    readonly tag="${CI_COMMIT_TAG:-}"
    readonly crate="${tag//\/*/}"
    readonly version="${tag#*/}"

    just ensure-command cargo mold

    if [[ -z "$tag" ]]; then
        printf "There is no tag!\n" >&2
        exit 1
    fi
    if [[ -z "$token" ]]; then
        printf "There is no token for crates.io!\n" >&2
        exit 1
    fi
    if ! just is-workspace-member "$crate" &>/dev/null; then
        printf "The crate %s is not a workspace member of the project!\n" "$crate" >&2
        exit 1
    fi

    readonly current_member_version="$(just get-workspace-member-version "$crate" 2>/dev/null)"
    if [[ "$version" != "$current_member_version" ]]; then
        printf "Current version in metadata of crate %s (%s) does not match the version from the tag (%s)!\n" "$crate" "$current_member_version" "$version"
        exit 1
    fi

    printf "Found tag %s (crate %s in version %s).\n" "$tag" "$crate" "$version"
    cargo publish -p "$crate"

# Creates a signing key and certificate for Secure Boot and verity signing if not both `key` and `cert` exist
[group('signstaros')]
create-image-signing-key key cert common_name="archlinux.org" key_settings="rsa:3072":
    if ! {{ path_exists(key) }}; then \
        if ! {{ path_exists(cert) }}; then \
            just ensure-command openssl; \
            mkdir -p resources/mkosi/signstar/mkosi.output/; \
            openssl req -x509 -newkey {{ key_settings }} -keyout "{{ key }}" -out "{{ cert }}" -nodes -days 3650 -set_serial 01 -subj /CN={{ common_name }}; \
        fi \
    fi

# Builds an OS image using mkosi
[group('signstaros')]
build-image openpgp_signing_key signing_key="resources/mkosi/signstar/mkosi.output/signing.key" signing_cert="resources/mkosi/signstar/mkosi.output/signing.pem" mkosi_options="":
    just ensure-command rsop mkosi

    just create-image-signing-key {{ absolute_path(signing_key) }} {{ absolute_path(signing_cert) }}
    cp {{ openpgp_signing_key }} {{ absolute_path("resources/mkosi/signstar/mkosi.extra/usr/lib/systemd/import-pubring.gpg") }}
    mkosi -f -C {{ absolute_path("resources/mkosi/signstar") }} {{ mkosi_options }} --secure-boot-key={{ absolute_path(signing_key) }} --secure-boot-certificate={{ absolute_path(signing_cert) }} --verity-key={{ absolute_path(signing_key) }} --verity-certificate={{ absolute_path(signing_cert) }} --key={{ openpgp_signing_key }} build

# Builds an OS image using mkosi
[group('signstaros')]
build-test-image openpgp_signing_key signing_key="resources/mkosi/signstar/mkosi.output/signing.key" signing_cert="resources/mkosi/signstar/mkosi.output/signing.pem" mkosi_options="":
    just build signstar-configure-build
    mkdir -p resources/mkosi/signstar/mkosi.profiles/local-testing/mkosi.extra/usr/local/bin/ resources/mkosi/signstar/mkosi.profiles/local-testing/mkosi.extra/usr/local/share/signstar/
    cp -v "${CARGO_TARGET_DIR:-target}/debug/signstar-configure-build" resources/mkosi/signstar/mkosi.profiles/local-testing/mkosi.extra/usr/local/bin/
    cp -v signstar-configure-build/tests/fixtures/example.toml resources/mkosi/signstar/mkosi.profiles/local-testing/mkosi.extra/usr/local/share/signstar/config.toml
    just build-image {{ openpgp_signing_key }} {{ signing_key }} {{ signing_cert }} "--profile local-testing"
    # mkosi -f -C {{ absolute_path("resources/mkosi/signstar") }} {{ mkosi_options }} --secure-boot-key={{ absolute_path(signing_key) }} --secure-boot-certificate={{ absolute_path(signing_cert) }} --verity-key={{ absolute_path(signing_key) }} --verity-certificate={{ absolute_path(signing_cert) }} --key={{ openpgp_signing_key }} --profile local-testing build

# Runs an OS image using mkosi qemu
[group('signstaros')]
run-image mkosi_options="" qemu_options="":
    # To forward the host port 2222 to Signstar's SSH port 22 use `just run-image '' '-netdev user,id=n1,hostfwd=tcp::2222-:22 -device virtio-net-pci,netdev=n1'`
    just ensure-command mkosi
    mkosi -C resources/mkosi/signstar/ {{ mkosi_options }} qemu {{ qemu_options }}

# Builds the documentation book using mdbook and stages all necessary rustdocs alongside
[group('build')]
build-book: docs
    #!/usr/bin/env bash
    set -euo pipefail

    just ensure-command mdbook mdbook-mermaid

    readonly target_dir="${CARGO_TARGET_DIR:-$PWD/target}"
    readonly output_dir="{{ output_dir }}"
    readonly rustdoc_dir="$output_dir/docs/rustdoc/"
    mapfile -t workspace_members < <(just get-workspace-members 2>/dev/null)

    mdbook-mermaid install resources/docs/
    mdbook build resources/docs/

    # move rust docs to their own namespaced dir
    mkdir -p "$rustdoc_dir"
    for name in "${workspace_members[@]}"; do
        cp -r "$target_dir/doc/${name//-/_}" "$rustdoc_dir"
    done
    cp -r "$target_dir/doc/"{search.desc,src,static.files,trait.impl,type.impl} "$rustdoc_dir"
    cp -r "$target_dir/doc/"*.{js,html} "$rustdoc_dir"

# Serves the documentation book using miniserve
[group('dev')]
serve-book: build-book
    just ensure-command miniserve
    miniserve --index=index.html {{ output_dir }}/docs

# Watches the documentation book contents and rebuilds on change using mdbook (useful for development)
[group('dev')]
watch-book:
    just ensure-command watchexec
    watchexec --exts md,toml,js --delay-run 5s :w
    just build-book

# Returns the target directory for cargo.
[private]
get-cargo-target-dir:
    just ensure-command cargo jq
    cargo metadata --format-version 1 | jq -r '.target_directory'

# Runs the tests that are made available with the "_containerized-integration-test" feature of all configured projects in a separate container
[group('test')]
containerized-integration-tests:
    #!/usr/bin/env bash
    set -euo pipefail

    readonly coverage="{{ coverage }}"

    if [[ "$coverage" == "true" ]]; then
        just ensure-command bash cargo cargo-llvm-cov cargo-nextest jq podman
        # Containerized integration tests require examples and bins to be built
        cargo build --examples --bins
        cargo llvm-cov --no-report nextest --features _containerized-integration-test --filterset 'kind(test)'
    else
        just ensure-command bash cargo cargo-nextest jq podman
        cargo nextest run --features _containerized-integration-test --filterset 'kind(test)'
    fi

# Creates code coverage for all projects.
[group('test')]
create-coverage-report mode="nodoc" metric="Test-coverage":
    #!/usr/bin/env bash
    set -euo pipefail

    target_dir="$(just get-cargo-target-dir)"

    mkdir --parents "$target_dir/llvm-cov/"

    just ensure-command cargo-llvm-cov cargo-nextest

    # Options for cargo
    cargo_options=(+stable)

    # The chosen reporting style (defaults to without doctest coverage)
    reporting_style="without doctest coverage"

    # Options for creating cobertura coverage report with cargo-llvm-cov
    cargo_llvm_cov_cobertura_options=(
        --cobertura
        --output-path "$target_dir/llvm-cov/cobertura-coverage.xml"
    )

    # Options for creating coverage report summary with cargo-llvm-cov
    cargo_llvm_cov_summary_options=(
        --json
        --summary-only
    )

    if [[ "{{ mode }}" == "doc" ]]; then
        reporting_style="with doctest coverage"
        # The support for doctest coverage is a nightly feature
        cargo_options=(+nightly)
        cargo_llvm_cov_cobertura_options+=(--doctests)
        cargo_llvm_cov_summary_options+=(--doctests)
    fi

    printf "Creating report %s\n" "$reporting_style"

    # Create cobertura coverage report
    cargo "${cargo_options[@]}" llvm-cov report "${cargo_llvm_cov_cobertura_options[@]}"

    # Get total coverage percentage from summary
    percentage="$(cargo "${cargo_options[@]}" llvm-cov report "${cargo_llvm_cov_summary_options[@]}" | jq '.data[0].totals.lines.percent')"

    # Trim percentage to 4 decimal places.
    percentage=$(LC_NUMERIC=C printf "%.4f\n" $percentage)

    # Writes to target/coverage-metrics.txt for Gitlab CI metric consumption.
    # https://docs.gitlab.com/ci/testing/metrics_reports/
    printf "{{ metric }} ${percentage}\n" > "$target_dir/llvm-cov/coverage-metrics.txt"
    printf "Test-coverage: ${percentage}%%\n"

# Runs the tests that are made available with the `_nethsm-integration-test` feature and for which the binary_id matches `::nethsm`
[group('test')]
nethsm-integration-tests *options:
    #!/usr/bin/env bash
    set -euo pipefail

    readonly coverage="{{ coverage }}"

    if [[ "$coverage" == "true" ]]; then
        just ensure-command bash cargo cargo-llvm-cov cargo-nextest jq podman
        # Containerized integration tests require examples and bins to be built
        cargo build --examples --bins
        cargo llvm-cov --no-report nextest --features _nethsm-integration-test --filterset 'kind(test) and binary_id(/::nethsm$/)' {{ options }}
    else
        just ensure-command bash cargo cargo-nextest jq podman
        cargo nextest run --features _nethsm-integration-test --filterset 'kind(test) and binary_id(/::nethsm$/)' {{ options }}
    fi

# Returns the short commit representing the latest GitHub release of the NetHSM image.
get-latest-nethsm-release-short-commit:
    #!/usr/bin/env bash
    set -euo pipefail

    just ensure-command curl jq

    latest_release="$(curl -s 'https://api.github.com/repos/nitrokey/nethsm/releases/latest' | jq -r '.tag_name')"
    short_commit="$(curl -s 'https://api.github.com/repos/nitrokey/nethsm/tags' | jq -r ".[] | select(.name == \"$latest_release\") | .commit.sha[:8]")"
    printf "%s\n" "$short_commit"
