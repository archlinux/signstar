use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    about = "Retrieve the info for a device",
    long_about = "Retrieve the info for a device

Retrieves the vendor and product information of the target device.

Requires no authentication."
)]
pub struct InfoCommand {}
