# Contributing

These are the contributing guidelines for the signstar project.

Development takes place at https://gitlab.archlinux.org/archlinux/signstar.

## Writing code

This project is written in [Rust] and formatted using the nightly [`rustfmt`] version.

All contributions are linted using [`clippy`] and spell checked using [`codespell`].
The dependencies are linted with [`cargo-deny`].
License identifiers and copyright statements are checked using [`reuse`].

Various [`just`] targets are used to run checks and tests.

To aide in development, it is encouraged to install the relevant [git pre-commit] and [git pre-push] hooks:

```shell
just add-hooks
```

## Writing commit messages

To ensure compatibility and automatic creation of [semantic versioning] compatible releases the commit message style follows [conventional commits].

## Creating releases

Releases are created by the developers of this project using [`release-plz`] by running (per package in the workspace):

```shell
$ release-plz update -p <package> -u
```

Changed files are added in a pull request towards the default branch.

Once the changes are merged to the default branch a tag is created for the respective package (with a prefix):

```shell
git tag -s <package>/<version>
git push --tags
```

Then the crate is published to https://crates.io:

```shell
cargo publish -p <package>
```

## License

All code contributions fall under the terms of the [Apache-2.0] and [MIT].

Configuration file contributions fall under the terms of the [CC0-1.0].

[Rust]: https://www.rust-lang.org/
[`rustfmt`]: https://github.com/rust-lang/rustfmt
[`clippy`]: https://github.com/rust-lang/rust-clippy
[`codespell`]: https://github.com/codespell-project/codespell
[`cargo-deny`]: https://github.com/EmbarkStudios/cargo-deny
[`reuse`]: https://git.fsfe.org/reuse/tool
[`just`]: https://github.com/casey/just
[git pre-commit]: https://man.archlinux.org/man/githooks.5#pre-commit
[git pre-push]: https://man.archlinux.org/man/githooks.5#pre-push
[semantic versioning]: https://semver.org/
[conventional commits]: https://www.conventionalcommits.org/en/v1.0.0/
[`release-plz`]: https://github.com/MarcoIeni/release-plz
[Apache-2.0]: ./LICENSES/Apache-2.0.txt
[MIT]: ./LICENSES/MIT.txt
[CC0-1.0]: ./LICENSES/CC0-1.0.txt
