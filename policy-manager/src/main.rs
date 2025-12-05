// src/main.rs
// Policy manager for Security Mode, written in Rust.
// It manages profiles: "agresywny", "bezpieczny", "monitor-only"
// Each profile defines capabilities, network, disk access.
// CLI commands: list, get <profile>
// Outputs JSON to stdout or to file in /tmp/Security-Mode/policy.json

use anyhow::{Context, Result};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

const TMP_DIR: &str = "/tmp/Security-Mode";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProfileConfig {
    capabilities: Vec<String>,
    network: String,
    disk_access: String,
}

fn get_profiles() -> HashMap<String, ProfileConfig> {
    let mut profiles = HashMap::new();
    profiles.insert(
        "agresywny".to_string(),
        ProfileConfig {
            capabilities: vec!["CAP_NET_ADMIN".to_string(), "CAP_SYS_ADMIN".to_string()],
            network: "bridge".to_string(),
            disk_access: "full".to_string(),
        },
    );
    profiles.insert(
        "bezpieczny".to_string(),
        ProfileConfig {
            capabilities: vec![],
            network: "isolated".to_string(),
            disk_access: "read-only".to_string(),
        },
    );
    profiles.insert(
        "monitor-only".to_string(),
        ProfileConfig {
            capabilities: vec![],
            network: "none".to_string(),
            disk_access: "none".to_string(),
        },
    );
    profiles
}

fn ensure_tmp_dir() -> Result<()> {
    std::fs::create_dir_all(TMP_DIR).context("Failed to create tmp dir")
}

fn write_json<P: AsRef<Path>, T: Serialize>(path: P, data: &T) -> Result<()> {
    let json = serde_json::to_string(data)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

fn handle_list() -> Result<()> {
    let profiles = get_profiles();
    let keys: Vec<String> = profiles.keys().cloned().collect();
    let data = HashMap::from([("profiles".to_string(), keys)]);
    let json = serde_json::to_string(&data)?;
    println!("{}", json);
    Ok(())
}

fn handle_get(profile: &str) -> Result<()> {
    let profiles = get_profiles();
    if let Some(config) = profiles.get(profile) {
        ensure_tmp_dir()?;
        write_json(format!("{}/policy.json", TMP_DIR), config)?;
        info!("Wrote policy for {} to {}/policy.json", profile, TMP_DIR);
        println!("{}", serde_json::to_string(config)?);
    } else {
        error!("Unknown profile: {}", profile);
        return Err(anyhow::anyhow!("Unknown profile"));
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: policy-manager <command> [args]");
        println!("Commands:");
        println!("  list              - List available profiles (JSON)");
        println!("  get <profile>     - Get config for profile and write to policy.json");
        return Ok(());
    }

    let command = &args[1];
    match command.as_str() {
        "list" => handle_list()?,
        "get" => {
            if args.len() > 2 {
                handle_get(&args[2])?;
            } else {
                error!("Missing profile for get command");
                return Err(anyhow::anyhow!("Missing profile"));
            }
        }
        _ => {
            error!("Unknown command: {}", command);
            return Err(anyhow::anyhow!("Unknown command"));
        }
    }

    Ok(())
}
