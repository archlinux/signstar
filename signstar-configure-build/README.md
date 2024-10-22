# Signstar configure build

A commandline tool to configure a Signstar system during build.

The scope of this project is to read a dedicated configuration file, derive system users and their integration from it and create them.

The `signstar-configure-build` executable must be run as root.

## Configuration file

By default `signstar-configure-build` relies on the configuration file `/usr/share/signstar/config.toml` and will fail if it is not found or not valid.

One of the following configuration files in the following order are used instead, if they exist:

- `/usr/local/share/signstar/config.toml`
- `/run/signstar/config.toml`
- `/etc/signstar/config.toml`

Alternatively, `signstar-configure-build` can be provided with a custom configuration file location using the `--config`/ `-c` option.

## System users

Based on configured user mappings in the configuration file, `signstar-configure-build`:

- creates unlocked system users
  - without passphrase
  - with a home directory below `/var/lib/signstar/home/` (but without creating it)
- adds [tmpfiles.d] integration for each user, so that their home directory is created automatically
- adds a dedicated [authorized_keys] file and [sshd_config] drop-in configuration, which defines a [ForceCommand] option to enforce specific commands for each configured user with SSH access

## Examples

<!--
```bash
mkdir -pv /usr/share/signstar/
cp -v tests/fixtures/example.toml /usr/share/signstar/config.toml
```
-->

Assuming a valid configuration file (such as [example.toml]) in one of the default locations, the executable is called without any options:

```bash
signstar-configure-build
```

<!--
```bash
remote_user_list=(
  ssh-wireguard-down
  ssh-metrics1
  ns1-ssh-operator1
  ssh-backup1
  ns1-ssh-operator2
  ssh-share-down
  ssh-operator1
  ssh-share-up
)
local_user_list=(
  local-metrics1
)

cat /etc/passwd
cat /usr/lib/tmpfiles.d/signstar-user-*.conf
cat /etc/ssh/signstar-user*.authorized_keys
cat /etc/ssh/sshd_config.d/10-signstar-user*.conf

for user in "${remote_user_list[@]}" "${local_user_list[@]}"; do
  grep -R "$user" /etc/passwd
  test -f "/usr/lib/tmpfiles.d/signstar-user-$user.conf"
done

for user in "${remote_user_list[@]}"; do
  test -f "/etc/ssh/signstar-user-$user.authorized_keys"
  test -f "/etc/ssh/sshd_config.d/10-signstar-user-$user.conf"
done
```
-->

[tmpfiles.d]: https://man.archlinux.org/man/tmpfiles.d.5
[authorized_keys]: https://man.archlinux.org/man/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
[sshd_config]: https://man.archlinux.org/man/sshd_config.5
[ForceCommand]: https://man.archlinux.org/man/sshd_config.5#ForceCommand
[example.toml]: tests/fixtures/example.toml
