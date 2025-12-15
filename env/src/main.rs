use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use nix::sys::stat::{mknod, Mode, SFlag};
use nix::unistd::{chdir, chroot, fork, getpid, getuid, mkdir, pivot_root, setsid, ForkResult, Pid};
use serde::{Deserialize, Serialize};
use serde_yaml;
use users::{get_user_by_name, User};
use anyhow::{anyhow, Context, Result};

#[derive(Debug, Deserialize, Serialize)]
struct Policy {
    network: bool,
    filesystem: Vec<String>,
    capabilities: Vec<String>,
    // Add more policy fields as needed
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(anyhow!("Usage: env <command> [args...]"));
    }

    let command = &args[1];
    match command.as_str() {
        "create" => create_isolated_env(&args[2..])?,
        "run" => run_in_isolated_env(&args[2..])?,
        _ => return Err(anyhow!("Unknown command: {}", command)),
    }

    Ok(())
}

fn create_isolated_env(args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(anyhow!("create requires a name for the environment"));
    }
    let env_name = &args[0];
    let base_path = PathBuf::from(format!("/tmp/isolated_{}", env_name));

    // Create directory structure
    fs::create_dir_all(&base_path).context("Failed to create base directory")?;

    // Mount a tmpfs for isolation
    mount(
        Some("tmpfs"),
        base_path.as_path(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ).context("Failed to mount tmpfs")?;

    // Setup basic filesystem structure
    let dirs = vec!["bin", "lib", "etc", "dev", "proc", "sys", "tmp"];
    for dir in dirs {
        mkdir(base_path.join(dir).as_path(), Mode::S_IRWXU).context(format!("Failed to mkdir {}", dir))?;
    }

    // Bind mount essential files/binaries if allowed by policy
    let policy = load_policy(env_name)?;
    if policy.filesystem.contains(&"/bin/sh".to_string()) {
        bind_mount("/bin/sh", base_path.join("bin/sh").as_path())?;
    }
    // Add more binds based on policy

    println!("Isolated environment '{}' created at {:?}", env_name, base_path);
    Ok(())
}

fn run_in_isolated_env(args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(anyhow!("run requires an environment name"));
    }
    let env_name = &args[0];
    let cmd_args = &args[1..];

    let policy = load_policy(env_name)?;

    // Unshare namespaces for isolation
    unshare(
        CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWIPC
            | if !policy.network { CloneFlags::CLONE_NEWNET } else { CloneFlags::empty() },
    ).context("Failed to unshare namespaces")?;

    // Setup user namespace mappings
    setup_user_mappings()?;

    // Fork to create a child process in the new namespaces
    match unsafe { fork() }.context("Failed to fork")? {
        ForkResult::Parent { child } => {
            // Wait for child
            nix::sys::wait::waitpid(child, None).context("Failed to wait for child")?;
        }
        ForkResult::Child => {
            // In child: setup isolated environment
            setsid().context("Failed to setsid")?;

            let base_path = PathBuf::from(format!("/tmp/isolated_{}", env_name));

            // Mount proc, sys, dev
            mount(Some("proc"), base_path.join("proc").as_path(), Some("proc"), MsFlags::empty(), None::<&str>)?;
            mount(Some("sysfs"), base_path.join("sys").as_path(), Some("sysfs"), MsFlags::empty(), None::<&str>)?;
            mount(Some("devtmpfs"), base_path.join("dev").as_path(), Some("devtmpfs"), MsFlags::empty(), None::<&str>)?;

            // Pivot root
            let old_root = base_path.join("old_root");
            mkdir(old_root.as_path(), Mode::S_IRWXU)?;
            pivot_root(base_path.as_path(), old_root.as_path()).context("Failed to pivot_root")?;

            // Chdir and chroot
            chdir(Path::new("/")).context("Failed to chdir to new root")?;
            chroot(Path::new("/")).context("Failed to chroot")?;

            // Drop capabilities based on policy
            drop_capabilities(&policy.capabilities)?;

            // Execute the command
            if !cmd_args.is_empty() {
                let mut cmd = Command::new(&cmd_args[0]);
                cmd.args(&cmd_args[1..]);
                cmd.exec().context("Failed to exec command")?;
            } else {
                // Default to shell
                Command::new("/bin/sh").exec().context("Failed to exec shell")?;
            }
        }
    }

    Ok(())
}

fn load_policy(env_name: &str) -> Result<Policy> {
    let policy_path = PathBuf::from(format!("~/.hackeros/Security-Mode/policy-security/{}.yaml", env_name));
    let expanded_path = shellexpand::tilde(&policy_path.to_string_lossy()).to_string();
    let file = File::open(expanded_path).context("Failed to open policy file")?;
    let policy: Policy = serde_yaml::from_reader(file).context("Failed to parse policy YAML")?;
    Ok(policy)
}

fn bind_mount(src: &str, dest: &Path) -> Result<()> {
    mount(Some(src), dest, None::<&str>, MsFlags::MS_BIND, None::<&str>).context("Failed to bind mount")
}

fn setup_user_mappings() -> Result<()> {
    // Write uid_map and gid_map for user namespace
    let uid = getuid();
    let mut uid_map = File::create("/proc/self/uid_map")?;
    uid_map.write_all(format!("0 {} 1\n", uid).as_bytes())?;

    let mut gid_map = File::create("/proc/self/gid_map")?;
    gid_map.write_all(format!("0 {} 1\n", uid).as_bytes())?; // Assuming same for gid

    // Deny setgroups
    let mut setgroups = File::create("/proc/self/setgroups")?;
    setgroups.write_all(b"deny")?;

    Ok(())
}

fn drop_capabilities(allowed_caps: &[String]) -> Result<()> {
    // This is a placeholder; in real Rust, use caps crate or similar for capability management
    // For now, assume we drop all except allowed
    println!("Dropping capabilities except: {:?}", allowed_caps);
    Ok(())
}
