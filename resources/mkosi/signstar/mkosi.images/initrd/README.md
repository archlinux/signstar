# Signstar OS initrd

This is a custom initrd for the Signstar OS.

It is customized to ensure, that [systemd-repart] is run in the initrd stage, after `sysroot.mount`.

[systemd-repart]: https://man.archlinux.org/man/systemd-repart.8
