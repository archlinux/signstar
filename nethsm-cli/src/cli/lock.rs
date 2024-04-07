// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use clap::Parser;
use nethsm::{SystemState, UserRole};

#[derive(Debug, Parser)]
#[command(
    about = "Lock a device",
    long_about = format!("Lock a device

After locking, the target device is in state \"{:?}\" and the unlock passphrase needs to be provided to return to state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", SystemState::Locked, SystemState::Operational, UserRole::Administrator),
)]
pub struct LockCommand;
