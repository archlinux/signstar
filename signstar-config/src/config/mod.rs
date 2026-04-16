//! Configuration file handling for _Signstar hosts_.

mod credentials;
pub mod error;
mod file;
pub mod state;
mod system;
mod traits;
mod utils;

pub use credentials::{AuthorizedKeyEntry, SystemUserId};
pub use file::{Config, ConfigBuilder, UserBackendConnection, UserBackendConnectionFilter};
pub use system::{SystemConfig, SystemUserMapping};
pub use traits::{
    BackendDomainFilter,
    BackendKeyIdFilter,
    BackendUserIdFilter,
    BackendUserIdKind,
    ConfigAuthorizedKeyEntries,
    ConfigSystemUserIds,
    Error as TraitsError,
    MappingAuthorizedKeyEntry,
    MappingBackendDomain,
    MappingBackendKeyId,
    MappingBackendUserIds,
    MappingBackendUserSecrets,
    MappingSystemUserId,
    NonAdminBackendUserIdFilter,
    NonAdminBackendUserIdKind,
};
pub(crate) use utils::{duplicate_authorized_keys, duplicate_system_user_ids};
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
pub(crate) use utils::{duplicate_backend_user_ids, duplicate_domains, duplicate_key_ids};
