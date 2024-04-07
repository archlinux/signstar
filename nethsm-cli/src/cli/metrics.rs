// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use clap::Parser;
use nethsm::UserRole;

#[derive(Debug, Parser)]
#[command(
    about = "Get metrics",
    long_about = format!("Get metrics

Metrics of the target device are returned in JSON format.

Requires authentication of a user in the \"{}\" role.", UserRole::Metrics),
)]
pub struct MetricsCommand {}
