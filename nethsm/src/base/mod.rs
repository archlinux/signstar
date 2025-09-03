//! Functionality for accessing a [`NetHsm`].

pub mod impl_base;
pub mod impl_key;
pub mod impl_noauth;
pub mod impl_openpgp;
pub mod impl_system;
pub mod impl_user;
pub mod utils;

use std::{cell::RefCell, collections::HashMap};

use ureq::Agent;

use crate::{Credentials, Url, UserId};

/// A network connection to a NetHSM.
///
/// Defines a network configuration for the connection and a list of user [`Credentials`] that can
/// be used over this connection.
#[derive(Debug)]
pub struct NetHsm {
    /// The agent for the requests
    agent: RefCell<Agent>,
    /// The URL path for the target API
    url: RefCell<Url>,
    /// The default [`Credentials`] to use for requests
    current_credentials: RefCell<Option<UserId>>,
    /// The list of all available credentials
    credentials: RefCell<HashMap<UserId, Credentials>>,
}
