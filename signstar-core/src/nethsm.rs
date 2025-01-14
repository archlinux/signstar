//! Defaults for NetHSM backends.

use std::net::Ipv4Addr;

use nethsm::LogLevel;

/// The default admin user name
pub const USER_DEFAULT_ADMIN: &str = "admin";

/// The default IP address of a NetHSM
pub const NETWORK_DEFAULT_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

/// The default netmask of a NetHSM
pub const NETWORK_DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// The default gateway of a NetHSM
pub const NETWORK_DEFAULT_GATEWAY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// The default logging IP address of a NetHSM
pub const LOGGING_DEFAULT_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// The default logging port of a NetHSM.
pub const LOGGING_DEFAULT_PORT: u32 = 514;

/// The default logging level of a NetHSM.
pub const LOGGING_DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Info;
