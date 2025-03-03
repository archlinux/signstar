//! SSH `known_hosts` format utilities.

use log::{info, warn};
use russh::keys::{
    PublicKey,
    ssh_key::known_hosts::{Entry, HostPatterns},
};

/// Checks whether a set of server details can be found in SSH `known_hosts` data.
///
/// Based on a `host` and its `port`, this function evaluates whether a supplied `key` is part of a
/// list of `entries` in the SSH known_hosts file format. Returns `true`, if the combination of
/// `key`, `host` and `port` matches an entry in the list of `entries` and that entry is not a CA
/// key or a revoked key. Returns `false` in all other cases.
pub(crate) fn is_server_known<'a>(
    entries: impl Iterator<Item = &'a Entry>,
    host: &str,
    port: u16,
    key: &PublicKey,
) -> bool {
    for entry in entries {
        if match entry.host_patterns() {
            HostPatterns::Patterns(items) => items
                .iter()
                .any(|item| item == host || item == &format!("[{host}]:{port}")),
            HostPatterns::HashedName { salt, hash } => {
                use hmac::Mac;
                if let Ok(mut mac) = hmac::Hmac::<sha1::Sha1>::new_from_slice(salt) {
                    mac.update(host.as_bytes());
                    mac.finalize().into_bytes()[..] == hash[..]
                } else {
                    warn!(
                        "the salt {salt:?} was not of correct size so the entry for host {host} does not match"
                    );
                    false
                }
            }
        } && entry.public_key() == key
        {
            return if let Some(marker) = entry.marker() {
                info!("Found marker {marker} for host {host} but it is not supported.");
                false
            } else {
                true
            };
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use testresult::TestResult;

    use super::*;

    #[test]
    fn test_single_entry() -> TestResult {
        let entry: Entry = "gitlab.archlinux.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy".parse()?;

        assert!(
            is_server_known(
                [entry].iter(),
                "gitlab.archlinux.org",
                22,
                &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy"
                    .parse()?
            ),
            "server should be known since there's one matching entry"
        );

        Ok(())
    }

    #[test]
    fn test_single_entry_with_port() -> TestResult {
        let entry: Entry = "[gitlab.archlinux.org]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy".parse()?;

        assert!(
            is_server_known(
                [entry].iter(),
                "gitlab.archlinux.org",
                22,
                &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy"
                    .parse()?
            ),
            "server should be known since there's one matching entry"
        );

        Ok(())
    }

    #[test]
    fn test_single_revoked_entry() -> TestResult {
        let entry: Entry = "@revoked gitlab.archlinux.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy".parse()?;

        assert!(
            !is_server_known(
                [entry].iter(),
                "gitlab.archlinux.org",
                22,
                &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy"
                    .parse()?
            ),
            "server should not be known since there's one matching entry but it is revoked"
        );

        Ok(())
    }

    #[test]
    fn test_single_cert_authority_entry() -> TestResult {
        let entry: Entry = "@cert-authority gitlab.archlinux.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy".parse()?;

        assert!(
            !is_server_known(
                [entry].iter(),
                "gitlab.archlinux.org",
                22,
                &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy"
                    .parse()?
            ),
            "server should not be known since certification authorities are not supported"
        );

        Ok(())
    }

    #[test]
    fn test_not_matching_entry() -> TestResult {
        let entry: Entry = "gitlab.archlinux.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K89dpNtltOK6vy".parse()?;

        assert!(
            !is_server_known(
                [entry].iter(),
                "gitlab.archlinux.org",
                22,
                &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy"
                    .parse()?
            ),
            "server should not be known since there are no matching entries"
        );

        Ok(())
    }

    #[test]
    fn test_not_matching_port_entry() -> TestResult {
        let entry: Entry = "[gitlab.archlinux.org]:23 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K89dpNtltOK6vy".parse()?;

        assert!(
            !is_server_known(
                [entry].iter(),
                "gitlab.archlinux.org",
                22,
                &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy"
                    .parse()?
            ),
            "server should not be known since there are no matching entries"
        );

        Ok(())
    }

    #[test]
    fn test_hashed_entry() -> TestResult {
        // entry generated using `ssh-keygen -H -F github.com`
        let entry: Entry = "|1|b8LfkX9Y09oxr9MMnQyfC9CtciI=|MnTpZgaon9ON5+hrylyRlq/li3Q= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl".parse()?;
        assert!(
            is_server_known(
                [entry].iter(),
                "github.com",
                22,
                &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                    .parse()?
            ),
            "server should be known since there's one matching entry"
        );

        Ok(())
    }
}
