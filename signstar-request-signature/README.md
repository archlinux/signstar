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
eval $(ssh-agent -a "$agent")

trap 'kill $SSH_AGENT_PID' EXIT INT TERM

# generate new key and add it to the agent
key_file=$(mktemp -u)
ssh-keygen -f "$key_file" -N ""
ssh-add "$key_file"
ssh-add -L | tee "tests/sshd/authorized_keys"

# build and run the dummy signstar server
image_id=$(mktemp)
podman --cgroup-manager cgroupfs build --iidfile "$image_id" tests/sshd
cid=$(mktemp)
podman run --rm  --cidfile "$cid" --detach --init -p 2222:2222 "$(cat $image_id)"

trap 'podman stop $(cat $cid)' EXIT INT TERM

sleep 1

known_hosts=$(mktemp)
ssh-keyscan -p 2222 127.0.0.1 | tee "$known_hosts"
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
