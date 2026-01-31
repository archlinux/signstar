//! Utility functions used in the context of the signstar-config config module.

use std::collections::HashSet;

use serde::{Serialize, Serializer};

#[cfg(feature = "_hsm-backend")]
use crate::config::{
    BackendDomainFilter,
    BackendKeyIdFilter,
    BackendUserIdFilter,
    BackendUserIdKind,
    MappingBackendDomain,
    MappingBackendKeyId,
    MappingBackendUserIds,
};
use crate::config::{MappingAuthorizedKeyEntry, MappingSystemUserId};

/// Serializes a [`HashSet`] of `T` as an ordered [`Vec`] of `T`.
pub(crate) fn ordered_set<S, T: Ord + Serialize>(
    value: &HashSet<T>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut ordered: Vec<_> = value.iter().collect();
    ordered.sort();
    ordered.serialize(serializer)
}

/// Collects all duplicate system user IDs.
///
/// Accepts a set of [`MappingSystemUserId`] implementations.
pub(crate) fn duplicate_system_user_ids(
    mappings: &HashSet<impl MappingSystemUserId>,
) -> Option<String> {
    let all_system_user_ids = mappings
        .iter()
        .filter_map(|mapping| mapping.system_user_id());
    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();

    for user_id in all_system_user_ids {
        if !seen.insert(user_id) {
            duplicates.insert(format!("\"{user_id}\""));
        }
    }

    if duplicates.is_empty() {
        None
    } else {
        let mut duplicates = Vec::from_iter(duplicates);
        duplicates.sort();
        Some(format!(
            "the duplicate system user ID{} {}",
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates.join(", ")
        ))
    }
}

/// Collects all duplicate SSH public keys used in as authorized_keys.
///
/// Accepts a set of [`MappingAuthorizedKeyEntry`] implementations.
///
/// # Note
///
/// Compares the actual [`KeyData`][ssh_key::public::KeyData] of the underlying
/// [`PublicKey`][ssh_key::public::PublicKey], because we are interested in whether there are direct
/// matches and we do not consider a public key comment an invariant.
/// The ssh-key upstream derives [`Eq`], [`Hash`], [`Ord`], [`PartialEq`] and [`PartialOrd`] for
/// [`PublicKey`][ssh_key::public::PublicKey] which means that public key comments are considered as
/// invariants, even if the [`KeyData`][ssh_key::public::KeyData] matches!
pub(crate) fn duplicate_authorized_keys(
    mappings: &HashSet<impl MappingAuthorizedKeyEntry>,
) -> Option<String> {
    let all_public_keys = mappings
        .iter()
        .filter_map(|mapping| mapping.authorized_key_entry())
        .map(|authorized_key_entry| authorized_key_entry.as_ref().public_key());
    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();

    for public_key in all_public_keys {
        if !seen.insert(public_key.key_data()) {
            let mut public_key = public_key.clone();
            // Unset the comment as it may be set to different values.
            public_key.set_comment("");
            duplicates.insert(format!("\"{}\"", public_key.to_string()));
        }
    }

    if duplicates.is_empty() {
        None
    } else {
        let mut duplicates = Vec::from_iter(duplicates);
        duplicates.sort();
        Some(format!(
            "the duplicate SSH public key{} {}",
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates.join(", ")
        ))
    }
}

/// Collects all duplicate backend user IDs.
///
/// Accepts a set of [`MappingBackendUserIds`] implementations.
#[cfg(feature = "_hsm-backend")]
pub(crate) fn duplicate_backend_user_ids(
    mappings: &HashSet<impl MappingBackendUserIds>,
) -> Option<String> {
    let all_backend_user_ids = mappings.iter().flat_map(|mapping| {
        mapping.backend_user_ids(BackendUserIdFilter {
            backend_user_id_kind: BackendUserIdKind::Any,
        })
    });
    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();

    for user_id in all_backend_user_ids {
        if !seen.insert(user_id.clone()) {
            duplicates.insert(format!("\"{user_id}\""));
        }
    }

    if duplicates.is_empty() {
        None
    } else {
        let mut duplicates = Vec::from_iter(duplicates);
        duplicates.sort();
        Some(format!(
            "the duplicate backend user ID{} {}",
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates.join(", ")
        ))
    }
}

/// Collects all duplicate backend key IDs.
///
/// Accepts a set of [`MappingBackendKeyId`] implementations.
/// Allows passing in an implementation of [`BackendKeyIdFilter`] as filter.
/// Optionally, a `key_type` can be passed in which is used to complete the sentence "the
/// duplicate{key_type} key ID".
#[cfg(feature = "_hsm-backend")]
pub(crate) fn duplicate_key_ids<T>(
    mappings: &HashSet<impl MappingBackendKeyId<T>>,
    filter: &T,
    key_type: Option<String>,
) -> Option<String>
where
    T: BackendKeyIdFilter,
{
    let all_system_wide_key_ids = mappings
        .iter()
        .filter_map(|mapping| mapping.backend_key_id(filter))
        .collect::<Vec<_>>();
    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();

    for key_id in all_system_wide_key_ids.iter() {
        if !seen.insert(key_id.as_str()) {
            duplicates.insert(format!("\"{key_id}\""));
        }
    }

    if duplicates.is_empty() {
        None
    } else {
        let mut duplicates = Vec::from_iter(duplicates);
        duplicates.sort();
        Some(format!(
            "the duplicate{} key ID{} {}",
            key_type.unwrap_or_default(),
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates.join(", ")
        ))
    }
}

/// Collects all duplicate domains.
///
/// Accepts a set of [`MappingBackendDomain`] implementations.
/// Allows passing in an implementation of [`BackendDomainFilter`] as filter.
/// Optionally, a `domain_context` and `domain_name` can be passed in which are used to complete the
/// sentence "the duplicate{domain_context} {domain_name}".
#[cfg(feature = "_hsm-backend")]
pub(crate) fn duplicate_domains<T>(
    mappings: &HashSet<impl MappingBackendDomain<T>>,
    filter: Option<&T>,
    domain_context: Option<String>,
    domain_name: Option<&str>,
) -> Option<String>
where
    T: BackendDomainFilter,
{
    let all_domains = mappings
        .iter()
        .filter_map(|mapping| mapping.backend_domain(filter))
        .collect::<Vec<String>>();
    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();

    for domain in all_domains.iter() {
        if !seen.insert(domain) {
            duplicates.insert(format!("\"{domain}\""));
        }
    }

    if duplicates.is_empty() {
        None
    } else {
        let mut duplicates = Vec::from_iter(duplicates);
        duplicates.sort();
        Some(format!(
            "the duplicate{} {}{} {}",
            domain_context.unwrap_or_default(),
            domain_name.unwrap_or("domain"),
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates.join(", ")
        ))
    }
}
