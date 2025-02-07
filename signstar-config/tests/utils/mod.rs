use std::{path::PathBuf, process::Command};

use signstar_core::system_user::HOME_BASE_DIR;
use testresult::TestResult;

/// Writes a dummy /etc/machine-id, which is required for systemd-creds.
pub fn write_machine_id() -> TestResult {
    println!("Write dummy /etc/machine-id, required for systemd-creds");
    let machine_id = PathBuf::from("/etc/machine-id");
    std::fs::write(&machine_id, "d3b07384d113edec49eaa6238ad5ff00")?;
    Ok(())
}

/// Installs packages using pacman.
pub fn install_packages(packages: &[&str]) -> TestResult {
    println!("Install packages: {:?}", packages);
    let install_params = {
        let mut params = Vec::from(["-Syu", "--needed", "--noconfirm"]);
        params.extend_from_slice(packages);
        params
    };

    // initialize the pacman keyring
    Command::new("pacman-key").arg("--init").output()?;

    // first update pacman-keyring
    Command::new("pacman")
        .args(["-Sy", "--needed", "--noconfirm", "archlinux-keyring"])
        .output()?;

    // then install all packages
    Command::new("pacman").args(install_params).output()?;

    Ok(())
}

/// Runs a command as a specific user.
pub fn run_command_as_user(command: &[&str], user: &str) -> TestResult {
    println!("Run command {:?} as user {:?}.", command, user);
    let run_params = {
        let mut params = Vec::from(["--uid", user, "--gid", user, "--same-dir", "--wait"]);
        params.extend_from_slice(command);
        params
    };

    // run command as user using systemd-run
    Command::new("systemd-run").args(run_params).output()?;

    Ok(())
}

/// Creates a set of users.
pub fn create_users(users: &[String]) -> TestResult {
    println!("Creating users: {:?}", users);
    for user in users {
        println!("Creating user: {}", user);
        // create the user and its home
        let useradd_output = Command::new("useradd")
            .args([
                "--base-dir",
                HOME_BASE_DIR,
                "--create-home",
                "--user-group",
                "--shell",
                "/usr/bin/bash",
                user,
            ])
            .output()?;
        println!(
            "useradd:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8(useradd_output.stdout)?,
            String::from_utf8(useradd_output.stderr)?
        );
        // unlock the user
        Command::new("usermod").args(["--unlock", user]).output()?;
    }

    Ok(())
}
