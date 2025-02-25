#!/bin/bash

set -Eeuxo pipefail

# start SSH agent
agent=$(mktemp -u)
eval $(ssh-agent -a "$agent")

# generate new key and add it to the agent
key_file=$(mktemp -u)
ssh-keygen -f "$key_file" -N ""
ssh-add "$key_file"
ssh-add -L | tee "tests/sshd/authorized_keys"

# build and run the dummy signstar server
image_id=$(mktemp)
podman build --iidfile "$image_id" tests/sshd
cid=$(mktemp)
podman run --rm  --cidfile "$cid" --detach --init -p 2222:2222 "$(cat $image_id)"

sleep 1

# get the
known_hosts=$(mktemp)
ssh-keyscan -p 2222 127.0.0.1 | tee "$known_hosts"

cargo run -- send --host 127.0.0.1 --port 2222 --user signstar-sign --agent-socket "$agent" --user-public-key "$(cat tests/sshd/authorized_keys | cut -d' ' -f 2)" --known-hosts "$known_hosts" Cargo.toml | jq

trap 'kill $SSH_AGENT_PID' EXIT INT TERM
trap 'podman stop $(cat $cid)' EXIT INT TERM
