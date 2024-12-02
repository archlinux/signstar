//! test

use russh::keys::{
    PublicKey,
    ssh_key::known_hosts::{Entry, HostPatterns},
};

pub(crate) fn is_server_known<'a>(
    entries: impl Iterator<Item = &'a Entry>,
    host: &str,
    key: &PublicKey,
) -> bool {
    for entry in entries {
        if match entry.host_patterns() {
            HostPatterns::Patterns(items) => items.iter().any(|item| item == host),
            HostPatterns::HashedName { salt, hash } => {
                use hmac::Mac;
                let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(salt).unwrap();
                mac.update(host.as_bytes());
                mac.finalize().into_bytes()[..] == hash[..]
            }
        } && entry.public_key() == key
        {
            return entry.marker().is_none();
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
                &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjT2SuA0k/xc5Cbyp+eBY5uN3bRL2K7GdpNtltOK6vy"
                    .parse()?
            ),
            "server should not be known since there's one matching entry but it is revoked"
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
                &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                    .parse()?
            ),
            "server should be known since there's one matching entry"
        );

        Ok(())
    }
}
