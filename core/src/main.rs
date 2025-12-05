// src/main.rs
// Core daemon for Security Mode, written in Rust.
// It runs as a systemd service, manages profiles and sandboxes.
// For now, polls /tmp/Security-Mode/ for JSON command files.
// Uses notify for watching the directory.
// Manages current profile, handles start/stop/status/logs.
// For sandboxing, uses nix to spawn processes in namespaces.

use anyhow::{Context, Result};
use cgroups_rs::{cgroup_builder::CgroupBuilder, hierarchies, Cgroup};
use log::{error, info};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult, Pid};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use tokio;  // For async, but using sync for simplicity now

const TMP_DIR: &str = "/tmp/Security-Mode";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Command {
    command: String,
    profile: Option<String>,
    timestamp: String,
    // For run_module
    module: Option<String>,
    args: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Status {
    running: bool,
    profile: String,
    timestamp: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProfileConfig {
    capabilities: Vec<String>,  // e.g., ["CAP_NET_ADMIN"]
    network: String,            // "bridge" or "isolated"
    disk_access: String,        // "full" or "read-only" or "none"
}

fn get_profile_config(profile: &str) -> ProfileConfig {
    match profile {
        "agresywny" => ProfileConfig {
            capabilities: vec!["CAP_NET_ADMIN".to_string(), "CAP_SYS_ADMIN".to_string()],
            network: "bridge".to_string(),
            disk_access: "full".to_string(),
        },
        "bezpieczny" => ProfileConfig {
            capabilities: vec![],
            network: "isolated".to_string(),
            disk_access: "read-only".to_string(),
        },
        "monitor-only" => ProfileConfig {
            capabilities: vec![],
            network: "none".to_string(),
            disk_access: "none".to_string(),
        },
        _ => ProfileConfig {
            capabilities: vec![],
            network: "isolated".to_string(),
            disk_access: "read-only".to_string(),
        },
    }
}

struct DaemonState {
    current_status: Status,
    logs: Vec<String>,
}

fn ensure_tmp_dir() -> Result<()> {
    fs::create_dir_all(TMP_DIR).context("Failed to create tmp dir")
}

fn write_json<P: AsRef<Path>, T: Serialize>(path: P, data: &T) -> Result<()> {
    let json = serde_json::to_string(data)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

fn read_json<P: AsRef<Path>, T: for<'de> Deserialize<'de>>(path: P) -> Result<T> {
    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn handle_start(profile: &str, state: &mut DaemonState) -> Result<()> {
    info!("Starting with profile: {}", profile);
    state.current_status = Status {
        running: true,
        profile: profile.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    write_json(format!("{}/status.json", TMP_DIR), &state.current_status)?;
    state.logs.push(format!("Started with profile: {}", profile));
    Ok(())
}

fn handle_stop(state: &mut DaemonState) -> Result<()> {
    info!("Stopping");
    state.current_status.running = false;
    write_json(format!("{}/status.json", TMP_DIR), &state.current_status)?;
    state.logs.push("Stopped".to_string());
    Ok(())
}

fn handle_logs_request(state: &DaemonState) -> Result<()> {
    info!("Logs requested");
    let logs_data: HashMap<String, Vec<String>> = [("logs".to_string(), state.logs.clone())].iter().cloned().collect();
    write_json(format!("{}/logs.json", TMP_DIR), &logs_data)?;
    Ok(())
}

fn handle_run_module(module: &str, args: &[String], profile: &str) -> Result<()> {
    info!("Running module: {} with args: {:?} under {}", module, args, profile);
    let config = get_profile_config(profile);

    // Simulate sandbox: use unshare for namespaces
    // This is simplified; in reality, drop caps, apply seccomp, etc.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            waitpid(child, None).unwrap();
        }
        Ok(ForkResult::Child) => {
            // In child: unshare namespaces
            unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS).unwrap();

            // Setup cgroups
            let hier = hierarchies::auto();
            let cg = CgroupBuilder::new("security_mode")
                .cpu()
                .shares(1024)
                .done()
                .build(hier)
                .unwrap();

            // Add current pid to cgroup
            let pid = cgroups_rs::CgroupPid::from(std::process::id() as u64);
            cg.add_task(pid).unwrap();

            // Run module-runner
            // Write module_command.json
            let command = Command {
                command: "run".to_string(),
                profile: Some(profile.to_string()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                module: Some(module.to_string()),
                args: Some(args.to_vec()),
            };
            write_json(format!("{}/module_command.json", TMP_DIR), &command)?;

            // Exec module-runner
            let module_runner_path = "/home/user/.hackeros/Security-Mode/bin/module-runner";  // Adjust path
            std::process::Command::new(module_runner_path)
                .exec();  // Replaces child process

            // If exec fails, exit
            std::process::exit(1);
        }
        Err(e) => {
            error!("Fork failed: {}", e);
        }
    }

    // After run, read output and log
    if let Ok(output) = read_json::<_, HashMap<String, String>>(format!("{}/module_output.json", TMP_DIR)) {
        info!("Module output: {:?}", output);
        // Append to logs or something
    }

    Ok(())
}

fn process_command_file(file: &Path, state: &mut DaemonState) -> Result<()> {
    let filename = file.file_name().unwrap().to_str().unwrap();
    match filename {
        "start.json" => {
            if let Ok(cmd) = read_json::<_, Command>(file) {
                if let Some(profile) = cmd.profile {
                    handle_start(&profile, state)?;
                }
            }
            fs::remove_file(file)?;
        }
        "stop.json" => {
            handle_stop(state)?;
            fs::remove_file(file)?;
        }
        "logs_request.json" => {
            handle_logs_request(state)?;
            fs::remove_file(file)?;
        }
        "run_module.json" => {
            if let Ok(cmd) = read_json::<_, Command>(file) {
                if let (Some(module), Some(args), Some(profile)) = (cmd.module, cmd.args, cmd.profile.or_else(|| Some(state.current_status.profile.clone()))) {
                    handle_run_module(&module, &args, &profile)?;
                }
            }
            fs::remove_file(file)?;
        }
        _ => {}
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    info!("Core daemon starting");

    ensure_tmp_dir()?;

    let state = Arc::new(Mutex::new(DaemonState {
        current_status: Status {
            running: false,
            profile: "none".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
        logs: vec![],
    }));

    // Write initial status
    write_json(format!("{}/status.json", TMP_DIR), &state.lock().unwrap().current_status)?;

    // Setup file watcher
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, notify::Config::default())?;
    watcher.watch(Path::new(TMP_DIR), RecursiveMode::NonRecursive)?;

    loop {
        match rx.recv() {
            Ok(event) => {
                if let Some(path) = event.paths.first() {
                    let mut state_guard = state.lock().unwrap();
                    if let Err(e) = process_command_file(path, &mut state_guard) {
                        error!("Error processing file: {}", e);
                    }
                }
            }
            Err(e) => error!("Watcher error: {}", e),
        }
    }

    Ok(())
}
