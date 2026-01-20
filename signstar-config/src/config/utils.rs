//! Utility functions used in the context of the signstar-config config module.

use std::collections::{BTreeSet, HashSet};

use ssh_key::PublicKey;

use crate::config::{
    BackendDomainFilter,
    BackendKeyIdFilter,
    BackendUserIdFilter,
    BackendUserIdKind,
    MappingAuthorizedKeyEntry,
    MappingBackendDomain,
    MappingBackendKeyId,
    MappingBackendUserIds,
    MappingSystemUserId,
};

/// Collects all duplicate items from an [`Iterator`] of type `T`.
fn collect_duplicates<'a, T>(data: impl Iterator<Item = &'a T>) -> Vec<&'a T>
where
    T: Eq + std::hash::Hash + Ord + 'a,
{
    let duplicates = {
        let mut seen = HashSet::new();
        let mut duplicates = HashSet::new();

        for thing in data {
            if !seen.insert(thing) {
                duplicates.insert(thing);
            }
        }
        duplicates
    };

    let mut output = Vec::from_iter(duplicates);
    output.sort();
    output
}

/// Collects all duplicate system user IDs.
///
/// Accepts a set of [`MappingSystemUserId`] implementations.
pub(crate) fn duplicate_system_user_ids(
    mappings: &BTreeSet<impl MappingSystemUserId>,
) -> Option<String> {
    let duplicates = collect_duplicates(
        mappings
            .iter()
            .filter_map(|mapping| mapping.system_user_id()),
    );

    if duplicates.is_empty() {
        None
    } else {
        Some(format!(
            "the duplicate system user ID{} {}",
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates
                .iter()
                .map(|id| format!("\"{id}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// Collects all duplicate SSH public keys used in `authorized_keys`.
///
/// Accepts a set of [`MappingAuthorizedKeyEntry`] implementations.
///
/// # Note
///
/// Compares the actual [`KeyData`][ssh_key::public::KeyData] of the underlying [`PublicKey`],
/// because we are interested in whether there are direct matches and we do not consider a public
/// key comment an invariant.
/// The ssh-key upstream derives [`Eq`], [`Hash`], [`Ord`], [`PartialEq`] and [`PartialOrd`] for
/// [`PublicKey`] which means that public key comments are considered as invariants, even if the
/// [`KeyData`][ssh_key::public::KeyData] matches!
pub(crate) fn duplicate_authorized_keys(
    mappings: &BTreeSet<impl MappingAuthorizedKeyEntry>,
) -> Option<String> {
    let all_key_data = mappings
        .iter()
        .filter_map(|mapping| mapping.authorized_key_entry())
        .map(|authorized_key_entry| authorized_key_entry.as_ref().public_key().key_data());
    let duplicates = collect_duplicates(all_key_data);

    if duplicates.is_empty() {
        None
    } else {
        Some(format!(
            "the duplicate SSH public key{} {}",
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates
                .into_iter()
                .map(|key_data| format!("\"{}\"", PublicKey::from(key_data.clone()).to_string()))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// Collects all duplicate backend user IDs.
///
/// Accepts a set of [`MappingBackendUserIds`] implementations.
pub(crate) fn duplicate_backend_user_ids(
    mappings: &BTreeSet<impl MappingBackendUserIds>,
) -> Option<String> {
    let all_backend_user_ids = mappings
        .iter()
        .flat_map(|mapping| {
            mapping.backend_user_ids(BackendUserIdFilter {
                backend_user_id_kind: BackendUserIdKind::Any,
            })
        })
        .collect::<Vec<_>>();
    let duplicates = collect_duplicates(all_backend_user_ids.iter());

    if duplicates.is_empty() {
        None
    } else {
        Some(format!(
            "the duplicate backend user ID{} {}",
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates
                .iter()
                .map(|id| format!("\"{id}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// Collects all duplicate backend key IDs.
///
/// Accepts a set of [`MappingBackendKeyId`] implementations.
/// Allows passing in an implementation of [`BackendKeyIdFilter`] as filter.
/// Optionally, a `key_type` can be passed in which is used to complete the sentence "the
/// duplicate{key_type} key ID".
pub(crate) fn duplicate_key_ids<T>(
    mappings: &BTreeSet<impl MappingBackendKeyId<T>>,
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
    let duplicates = collect_duplicates(all_system_wide_key_ids.iter());

    if duplicates.is_empty() {
        None
    } else {
        Some(format!(
            "the duplicate{} key ID{} {}",
            key_type.unwrap_or_default(),
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates
                .iter()
                .map(|id| format!("\"{id}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// Collects all duplicate domains.
///
/// Accepts a set of [`MappingBackendDomain`] implementations.
/// Allows passing in an implementation of [`BackendDomainFilter`] as filter.
/// Optionally, a `domain_context` and `domain_name` can be passed in which are used to complete the
/// sentence "the duplicate{domain_context} {domain_name}".
pub(crate) fn duplicate_domains<T>(
    mappings: &BTreeSet<impl MappingBackendDomain<T>>,
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
    let duplicates = collect_duplicates(all_domains.iter());

    if duplicates.is_empty() {
        None
    } else {
        Some(format!(
            "the duplicate{} {}{} {}",
            domain_context.unwrap_or_default(),
            domain_name.unwrap_or("domain"),
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates
                .iter()
                .map(|domain| format!("\"{domain}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}
