# Signstar Request Signature

This crate offers a library and an executable for creating, reading and writing of signing requests for files.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_request_signature/> for development version of the crate
- <https://docs.rs/signstar_request_signature/> for released versions of the crate

## Preparing signing request

The tool can be used to prepare a raw JSON signing request:

```bash
signstar-request-signature prepare Cargo.toml
```

## Sending the signing request over SSH

Additionally it's possible to prepare the signing request and send it over SSH in one command.

<!--
```bash
# start SSH agent
agent=$(mktemp -u)
eval "$(ssh-agent -a "$agent")"

trap 'kill $SSH_AGENT_PID' EXIT INT TERM

# generate new key and add it to the agent
key_file=$(mktemp -u)
ssh-keygen -f "$key_file" -N ""
ssh-add "$key_file"
ssh-add -L > "tests/sshd/authorized_keys"

set +x
counter=0
until ssh-keyscan -p 2222 127.0.0.1 2> /dev/null; do
  printf "Test container is not ready, waiting (try %d)...\n" "$counter"
  sleep 1
  counter=$(( counter + 1 ))
  # we need a high value here since the entire openssh server installation and setup
  # is happening while we wait
  if (( counter > 50 )); then
    printf "Test container is not up even after 30 tries. Aborting."
    set -x
    exit 2
  fi
done
set -x

known_hosts=$(mktemp)
ssh-keyscan -p 2222 127.0.0.1 > "$known_hosts"
```
-->
`send` subcommand requires parameters related to SSH session:

```bash
signstar-request-signature send --host 127.0.0.1 --port 2222 --user signstar-sign \
  --agent-socket "$agent" --user-public-key "$(cat tests/sshd/authorized_keys)" \
  --known-hosts "$known_hosts" Cargo.toml | jq
```

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[contributing guidelines]: ../CONTRIBUTING.md
