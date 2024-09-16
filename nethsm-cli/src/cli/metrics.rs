use clap::Parser;
use expression_format::ex_format;
use nethsm::UserRole::Metrics;

#[derive(Debug, Parser)]
#[command(
    about = "Get metrics",
    long_about = ex_format!("Get metrics

Metrics of the target device are returned in JSON format.

Requires authentication of a system-wide user in the \"{Metrics}\" role."),
)]
pub struct MetricsCommand {}
