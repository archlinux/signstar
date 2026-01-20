//! Configuration file handling for _Signstar hosts_.

pub mod base;
pub mod credentials;
pub mod error;
pub mod mapping;
pub mod state;
mod traits;

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
