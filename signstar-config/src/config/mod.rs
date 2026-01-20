//! Configuration file handling for _Signstar hosts_.

pub mod base;
pub mod credentials;
pub mod error;
pub mod mapping;
pub mod state;
mod traits;
mod utils;

pub use traits::{
    BackendDomainFilter,
    BackendKeyIdFilter,
    BackendUserIdFilter,
    BackendUserIdKind,
    ConfigAuthorizedKeyEntries,
    ConfigSystemUserIds,
    MappingAuthorizedKeyEntry,
    MappingBackendDomain,
    MappingBackendKeyId,
    MappingBackendUserIds,
    MappingBackendUserSecrets,
    MappingSystemUserId,
};
pub(crate) use utils::{
    duplicate_authorized_keys,
    duplicate_backend_user_ids,
    duplicate_domains,
    duplicate_key_ids,
    duplicate_system_user_ids,
    ordered_set,
};
