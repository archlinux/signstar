use std::net::Ipv4Addr;

use nethsm::LogLevel;

/// The default admin user name
pub static USER_DEFAULT_ADMIN: &str = "admin";

/// The default IP address of a NetHSM
pub static NETWORK_DEFAULT_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

/// The default netmask of a NetHSM
pub static NETWORK_DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// The default gateway of a NetHSM
pub static NETWORK_DEFAULT_GATEWAY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// The default IP address of a NetHSM
pub static LOGGING_DEFAULT_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// The default netmask of a NetHSM
pub static LOGGING_DEFAULT_PORT: u32 = 514;

/// The default gateway of a NetHSM
pub static LOGGING_DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Info;